package main

import (
	"fmt"
	"sync"

	"github.com/subgraph/fw-daemon/nfqueue"
	"github.com/subgraph/go-procsnitch"
	"net"
)

type pendingConnection interface {
	policy() *Policy
	procInfo() *procsnitch.Info
	hostname() string
	dst() net.IP
	dstPort() uint16
	accept()
	drop()
	print() string
}

type pendingPkt struct {
	pol   *Policy
	name  string
	pkt   *nfqueue.Packet
	pinfo *procsnitch.Info
}

func (pp *pendingPkt) policy() *Policy {
	return pp.pol
}

func (pp *pendingPkt) procInfo() *procsnitch.Info {
	return pp.pinfo
}

func (pp *pendingPkt) hostname() string {
	return pp.name
}
func (pp *pendingPkt) dst() net.IP {
	return pp.pkt.Dst
}

func (pp *pendingPkt) dstPort() uint16 {
	return pp.pkt.DstPort
}

func (pp *pendingPkt) accept() {
	pp.pkt.Accept()
}

func (pp *pendingPkt) drop() {
	pp.pkt.Mark = 1
	pp.pkt.Accept()
}

func (pp *pendingPkt) print() string {
	return printPacket(pp.pkt, pp.name)
}

type Policy struct {
	fw               *Firewall
	path             string
	application      string
	icon             string
	rules            RuleList
	pendingQueue     []pendingConnection
	promptInProgress bool
	lock             sync.Mutex
}

func (fw *Firewall) PolicyForPath(path string) *Policy {
	fw.lock.Lock()
	defer fw.lock.Unlock()

	return fw.policyForPath(path)
}

func (fw *Firewall) policyForPath(path string) *Policy {
	if _, ok := fw.policyMap[path]; !ok {
		p := new(Policy)
		p.fw = fw
		p.path = path
		p.application = path
		entry := entryForPath(path)
		if entry != nil {
			p.application = entry.name
			p.icon = entry.icon
		}
		fw.policyMap[path] = p
		fw.policies = append(fw.policies, p)
	}
	return fw.policyMap[path]
}

func (p *Policy) processPacket(pkt *nfqueue.Packet, pinfo *procsnitch.Info) {
	p.lock.Lock()
	defer p.lock.Unlock()
	name := p.fw.dns.Lookup(pkt.Dst)
	if !logRedact {
		log.Info("Lookup(%s): %s", pkt.Dst.String(), name)
	}
	result := p.rules.filterPacket(pkt, pinfo, name)
	switch result {
	case FILTER_DENY:
		pkt.Mark = 1
		pkt.Accept()
	case FILTER_ALLOW:
		pkt.Accept()
	case FILTER_PROMPT:
		p.processPromptResult(&pendingPkt{pol: p, name: name, pkt: pkt, pinfo: pinfo})
	default:
		log.Warning("Unexpected filter result: %d", result)
	}
}

func (p *Policy) processPromptResult(pc pendingConnection) {
	p.pendingQueue = append(p.pendingQueue, pc)
	if !p.promptInProgress {
		p.promptInProgress = true
		go p.fw.dbus.prompt(p)
	}
}

func (p *Policy) nextPending() pendingConnection {
	p.lock.Lock()
	defer p.lock.Unlock()
	if len(p.pendingQueue) == 0 {
		return nil
	}
	return p.pendingQueue[0]
}

func (p *Policy) removePending(pc pendingConnection) {
	p.lock.Lock()
	defer p.lock.Unlock()

	remaining := []pendingConnection{}
	for _, c := range p.pendingQueue {
		if c != pc {
			remaining = append(remaining, c)
		}
	}
	if len(remaining) != len(p.pendingQueue) {
		p.pendingQueue = remaining
	}
}

func (p *Policy) processNewRule(r *Rule, scope int32) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	if scope != APPLY_ONCE {
		p.rules = append(p.rules, r)
	}

	p.filterPending(r)
	if len(p.pendingQueue) == 0 {
		p.promptInProgress = false
	}

	return p.promptInProgress
}

func (p *Policy) parseRule(s string, add bool) (*Rule, error) {
	r := new(Rule)
	r.policy = p
	if !r.parse(s) {
		return nil, parseError(s)
	}
	if add {
		p.lock.Lock()
		defer p.lock.Unlock()
		p.rules = append(p.rules, r)
	}
	p.fw.addRule(r)
	return r, nil
}

func (p *Policy) removeRule(r *Rule) {
	p.lock.Lock()
	defer p.lock.Unlock()

	var newRules RuleList
	for _, rr := range p.rules {
		if rr.id != r.id {
			newRules = append(newRules, rr)
		}
	}
	p.rules = newRules
}

func (p *Policy) filterPending(rule *Rule) {
	remaining := []pendingConnection{}
	for _, pc := range p.pendingQueue {
		if rule.match(pc.dst(), pc.dstPort(), pc.hostname()) {
			log.Info("Also applying %s to %s", rule.getString(logRedact), pc.print())
			if rule.rtype == RULE_ALLOW {
				pc.accept()
			} else {
				pc.drop()
			}
		} else {
			remaining = append(remaining, pc)
		}
	}
	if len(remaining) != len(p.pendingQueue) {
		p.pendingQueue = remaining
	}
}

func (p *Policy) hasPersistentRules() bool {
	for _, r := range p.rules {
		if !r.sessionOnly {
			return true
		}
	}
	return false
}

func printPacket(pkt *nfqueue.Packet, hostname string) string {
	proto := func() string {
		switch pkt.Protocol {
		case nfqueue.TCP:
			return "TCP"
		case nfqueue.UDP:
			return "UDP"
		default:
			return "???"
		}
	}()

	if logRedact {
		hostname = "[redacted]"
	}
	name := hostname
	if name == "" {
		name = pkt.Dst.String()
	}
	return fmt.Sprintf("(%s %s:%d --> %s:%d)", proto, pkt.Src, pkt.SrcPort, name, pkt.DstPort)
}

func (fw *Firewall) filterPacket(pkt *nfqueue.Packet) {
	if pkt.Protocol == nfqueue.UDP && pkt.SrcPort == 53 {
		pkt.Accept()
		fw.dns.processDNS(pkt)
		return
	}
	pinfo := findProcessForPacket(pkt)
	if pinfo == nil {
		log.Warning("No proc found for %s", printPacket(pkt, fw.dns.Lookup(pkt.Dst)))
		pkt.Accept()
		return
	}
	log.Debug("filterPacket [%s] %s", pinfo.ExePath, printPacket(pkt, fw.dns.Lookup(pkt.Dst)))
	if basicAllowPacket(pkt) {
		pkt.Accept()
		return
	}
	policy := fw.PolicyForPath(pinfo.ExePath)
	policy.processPacket(pkt, pinfo)
}

func findProcessForPacket(pkt *nfqueue.Packet) *procsnitch.Info {
	switch pkt.Protocol {
	case nfqueue.TCP:
		return procsnitch.LookupTCPSocketProcess(pkt.SrcPort, pkt.Dst, pkt.DstPort)
	case nfqueue.UDP:
		return procsnitch.LookupUDPSocketProcess(pkt.SrcPort)
	default:
		log.Warning("Packet has unknown protocol: %d", pkt.Protocol)
		return nil
	}
}

func basicAllowPacket(pkt *nfqueue.Packet) bool {
	return pkt.Dst.IsLoopback() ||
		pkt.Dst.IsLinkLocalMulticast() ||
		pkt.Protocol != nfqueue.TCP
}
