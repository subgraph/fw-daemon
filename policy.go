package main

import (
	"fmt"
	"sync"

	"github.com/subgraph/fw-daemon/nfqueue"
)

type pendingPkt struct {
	policy   *Policy
	hostname string
	pkt      *nfqueue.Packet
	proc     *ProcInfo
}

type Policy struct {
	fw               *Firewall
	path             string
	application      string
	icon             string
	rules            RuleList
	pendingQueue     []*pendingPkt
	promptInProgress bool
	lock             sync.Mutex
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

func (p *Policy) processPacket(pkt *nfqueue.Packet, proc *ProcInfo) {
	p.lock.Lock()
	defer p.lock.Unlock()
	name := p.fw.dns.Lookup(pkt.Dst)
	log.Info("Lookup(%s): %s", pkt.Dst.String(), name)
	result := p.rules.filter(pkt, proc, name)
	switch result {
	case FILTER_DENY:
		pkt.Mark = 1
		pkt.Accept()
	case FILTER_ALLOW:
		pkt.Accept()
	case FILTER_PROMPT:
		p.processPromptResult(&pendingPkt{policy: p, hostname: name, pkt: pkt, proc: proc})
	default:
		log.Warning("Unexpected filter result: %d", result)
	}
}

func (p *Policy) processPromptResult(pp *pendingPkt) {
	p.pendingQueue = append(p.pendingQueue, pp)
	if !p.promptInProgress {
		p.promptInProgress = true
		go p.fw.dbus.prompt(p)
	}
}

func (p *Policy) nextPending() *pendingPkt {
	p.lock.Lock()
	defer p.lock.Unlock()
	if len(p.pendingQueue) == 0 {
		return nil
	}
	return p.pendingQueue[0]
}

func (p *Policy) removePending(pp *pendingPkt) {
	p.lock.Lock()
	defer p.lock.Unlock()

	remaining := []*pendingPkt{}
	for _, pkt := range p.pendingQueue {
		if pkt != pp {
			remaining = append(remaining, pkt)
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

func (p *Policy) filterPending(rule *Rule) {
	remaining := []*pendingPkt{}
	for _, pp := range p.pendingQueue {
		if rule.match(pp.pkt, pp.hostname) {
			log.Info("Also applying %s to %s", rule, printPacket(pp.pkt, pp.hostname))
			if rule.rtype == RULE_ALLOW {
				pp.pkt.Accept()
			} else {
				pp.pkt.Mark = 1
				pp.pkt.Accept()
			}
		} else {
			remaining = append(remaining, pp)
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
	proc := findProcessForPacket(pkt)
	if proc == nil {
		log.Warning("No proc found for %s", printPacket(pkt, fw.dns.Lookup(pkt.Dst)))
		pkt.Accept()
		return
	}
	log.Debug("filterPacket [%s] %s", proc.exePath, printPacket(pkt, fw.dns.Lookup(pkt.Dst)))
	if basicAllowPacket(pkt) {
		pkt.Accept()
		return
	}
	fw.lock.Lock()
	policy := fw.policyForPath(proc.exePath)
	fw.lock.Unlock()
	policy.processPacket(pkt, proc)
}

func basicAllowPacket(pkt *nfqueue.Packet) bool {
	return pkt.Dst.IsLoopback() ||
		pkt.Dst.IsLinkLocalMulticast() ||
		pkt.Protocol != nfqueue.TCP
}
