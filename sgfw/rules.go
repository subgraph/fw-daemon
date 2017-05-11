package sgfw

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode"
	"regexp"

	nfqueue "github.com/subgraph/go-nfnetlink/nfqueue"
//	"github.com/subgraph/go-nfnetlink"
	"github.com/subgraph/go-procsnitch"
)

const matchAny = 0
const noAddress = uint32(0xffffffff)

type Rule struct {
	id       uint
	policy   *Policy
	mode     RuleMode
	rtype    RuleAction
	hostname string
	network  *net.IPNet
	addr     uint32
	saddr    net.IP
	port     uint16
}

func (r *Rule) String() string {
	return r.getString(false)
}

func (r *Rule) getString(redact bool) string {
	rtype := RuleActionString[RULE_ACTION_DENY]
	if r.rtype == RULE_ACTION_ALLOW {
		rtype = RuleActionString[RULE_ACTION_ALLOW]
	}
	rmode := ""
	if r.mode == RULE_MODE_SYSTEM {
		rmode = "|" + RuleModeString[RULE_MODE_SYSTEM]
	}

	return fmt.Sprintf("%s|%s%s", rtype, r.AddrString(redact), rmode)
}

func (r *Rule) AddrString(redact bool) string {
	addr := "*"
	port := "*"
	if r.hostname != "" {
		addr = r.hostname
	} else if r.network != nil {
		addr = r.network.String()
	} else if r.addr != matchAny && r.addr != noAddress {
		bs := make([]byte, 4)
		binary.BigEndian.PutUint32(bs, r.addr)
		addr = fmt.Sprintf("%d.%d.%d.%d", bs[0], bs[1], bs[2], bs[3])
	}

	if r.port != matchAny {
		port = fmt.Sprintf("%d", r.port)
	}

	if redact && addr != "*" {
		addr = STR_REDACTED
	}

	return fmt.Sprintf("%s:%s", addr, port)
}

type RuleList []*Rule

func (r *Rule) match(src net.IP, dst net.IP, dstPort uint16, hostname string) bool {

xip := make(net.IP, 4)
binary.BigEndian.PutUint32(xip, r.addr)
log.Notice("comparison: ", hostname, " / ", dst, " : ", dstPort, " -> ", xip, " / ", r.hostname, " : ", r.port)
	if r.port != matchAny && r.port != dstPort {
		return false
	}
	if r.addr == matchAny {
		return true
	}
	if r.hostname != "" {
		if strings.ContainsAny(r.hostname, "*") {
			regstr := strings.Replace(r.hostname, "*", ".?", -1)
			match, err := regexp.MatchString(regstr, hostname)

			if err != nil {
				log.Errorf("Error comparing hostname against mask %s: %v", regstr, err)
			} else {
				return match
			}
		}
		return r.hostname == hostname
	}
	if r.network != nil && r.network.Contains(dst) {
		return true
	}
	return r.addr == binary.BigEndian.Uint32(dst.To4())
}

func (rl *RuleList) filterPacket(p *nfqueue.NFQPacket, pinfo *procsnitch.Info, srcip net.IP, hostname, optstr string) FilterResult {
	_, dstip := getPacketIP4Addrs(p)
	_, dstp := getPacketPorts(p)
	return rl.filter(p, srcip, dstip, dstp, hostname, pinfo, optstr)
}

func (rl *RuleList) filter(pkt *nfqueue.NFQPacket, src, dst net.IP, dstPort uint16, hostname string, pinfo *procsnitch.Info, optstr string) FilterResult {
	if rl == nil {
		return FILTER_PROMPT
	}
	result := FILTER_PROMPT
	sandboxed := strings.HasPrefix(optstr, "Sandbox")
	for _, r := range *rl {
log.Notice("------------ trying match of src ", src, " against: ", r, " | ", r.saddr, " / optstr = ", optstr)
		if r.saddr == nil && src != nil && sandboxed {
log.Notice("! Skipping comparison against incompatible rule types: rule src = ", r.saddr, " / packet src = ", src)
			continue
		} else if r.saddr != nil && !r.saddr.Equal(src) {
log.Notice("! Skipping comparison of mismatching source ips")
			continue
		}
		if r.match(src, dst, dstPort, hostname) {
log.Notice("+ MATCH SUCCEEDED")
			dstStr := dst.String()
			if FirewallConfig.LogRedact {
				dstStr = STR_REDACTED
			}
			srcStr := STR_UNKNOWN
			if pkt != nil {
				srcip, _ := getPacketIP4Addrs(pkt)
				srcp, _ := getPacketPorts(pkt)
				srcStr = fmt.Sprintf("%s:%d", srcip, srcp)
			}
			log.Noticef("%s > %s %s %s -> %s:%d",
				r.getString(FirewallConfig.LogRedact),
				pinfo.ExePath, "TCP",
				srcStr,
				dstStr, dstPort)
			if r.rtype == RULE_ACTION_DENY {
			log.Warningf("DENIED outgoing connection attempt by %s from %s %s -> %s:%d",
				pinfo.ExePath, "TCP",
				srcStr,
				dstStr, dstPort)
				return FILTER_DENY
			} else if r.rtype == RULE_ACTION_ALLOW {
				result = FILTER_ALLOW

				if r.saddr != nil {
					return result
				}
			}
		} else { log.Notice("+ MATCH FAILED") }
	}
log.Notice("--- RESULT = ", result)
	return result
}

func parseError(s string) error {
	return fmt.Errorf("unable to parse rule string: %s", s)
}

func (r *Rule) parse(s string) bool {
	r.addr = noAddress
	r.saddr = nil
	parts := strings.Split(s, "|")
	if len(parts) < 2 {
		return false
	}
	if len(parts) >= 3 && parts[2] == "SYSTEM" {
		r.mode = RULE_MODE_SYSTEM

		if len(parts) > 4 {
			r.saddr = net.ParseIP(parts[3])
		}

	} else if len(parts) > 3 {
			r.saddr = net.ParseIP(parts[3])
	} else if len(parts) > 2 {
			r.saddr = net.ParseIP(parts[2])
	}

	return r.parseVerb(parts[0]) && r.parseTarget(parts[1])
}

func (r *Rule) parseVerb(v string) bool {
	switch v {
	case RuleActionString[RULE_ACTION_ALLOW]:
		r.rtype = RULE_ACTION_ALLOW
		return true
	case RuleActionString[RULE_ACTION_DENY]:
		r.rtype = RULE_ACTION_DENY
		return true
	}
	return false
}

func (r *Rule) parseTarget(t string) bool {
	addrPort := strings.Split(t, ":")
	if len(addrPort) != 2 {
		return false
	}

	return r.parseAddr(addrPort[0]) && r.parsePort(addrPort[1])
}

func (r *Rule) parseAddr(a string) bool {
	if a == "*" {
		r.hostname = ""
		r.addr = matchAny
		return true
	}
	if strings.IndexFunc(a, unicode.IsLetter) != -1 {
		r.hostname = a
		return true
	}
//	ip := net.ParseIP(a)
	ip, ipnet, err := net.ParseCIDR(a)
	if err != nil || ip == nil {
		return false
	}
	r.network = ipnet
	r.addr = binary.BigEndian.Uint32(ip.To4())
	return true
}

func (r *Rule) parsePort(p string) bool {
	if p == "*" {
		r.port = matchAny
		return true
	}
	var err error
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil || port == 0 || port > 0xFFFF {
		return false
	}
	r.port = uint16(port)
	return true
}

const ruleFile = "/var/lib/sgfw/sgfw_rules"

func maybeCreateDir(dir string) error {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return os.MkdirAll(dir, 0755)
	}
	return err
}

func rulesPath() (string, error) {
	if err := maybeCreateDir(path.Dir(ruleFile)); err != nil {
		return ruleFile, err
	}
	return ruleFile, nil
}

func (fw *Firewall) saveRules() {
	fw.lock.Lock()
	defer fw.lock.Unlock()

	p, err := rulesPath()
	if err != nil {
		log.Warningf("Failed to open %s for writing: %v", p, err)
		return
	}
	f, err := os.Create(p)
	if err != nil {
		log.Warningf("Failed to open %s for writing: %v", p, err)
		return
	}
	defer f.Close()

	for _, p := range fw.policies {
		savePolicy(f, p)
	}
}

func savePolicy(f *os.File, p *Policy) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if !p.hasPersistentRules() {
		return
	}

	if !writeLine(f, "["+p.path+"]") {
		return
	}
	for _, r := range p.rules {
		if r.mode != RULE_MODE_SESSION {
			if !writeLine(f, r.String()) {
				return
			}
		}
	}
}

func writeLine(f *os.File, line string) bool {
	_, err := f.WriteString(line + "\n")
	if err != nil {
		log.Warningf("Error writing to rule file: %v", err)
		return false
	}
	return true
}

func (fw *Firewall) loadRules() {
	fw.lock.Lock()
	defer fw.lock.Unlock()

	fw.clearRules()

	p, err := rulesPath()
	if err != nil {
		log.Warningf("Failed to open %s for reading: %v", p, err)
		return
	}
	bs, err := ioutil.ReadFile(p)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warningf("Failed to open %s for reading: %v", p, err)
		}
		return
	}
	var policy *Policy
	for _, line := range strings.Split(string(bs), "\n") {
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			policy = fw.processPathLine(line)
		} else if len(strings.TrimSpace(line)) > 0 {
			processRuleLine(policy, line)
		}
	}
}

func (fw *Firewall) processPathLine(line string) *Policy {
	path := line[1 : len(line)-1]
	policy := fw.policyForPath(path)
	policy.lock.Lock()
	defer policy.lock.Unlock()
	policy.rules = nil
	return policy
}

func processRuleLine(policy *Policy, line string) {
	if policy == nil {
		log.Warningf("Cannot process rule line without first seeing path line: %s", line)
		return
	}
	_, err := policy.parseRule(line, true)
	if err != nil {
		log.Warningf("Error parsing rule (%s): %v", line, err)
		return
	}
}
