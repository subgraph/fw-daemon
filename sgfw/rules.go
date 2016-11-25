package main

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

	"github.com/subgraph/fw-daemon/nfqueue"
	"github.com/subgraph/go-procsnitch"
)

const (
	RULE_DENY = iota
	RULE_ALLOW
)

const matchAny = 0
const noAddress = uint32(0xffffffff)

type RuleMode uint16

const (
	RULE_MODE_SESSION RuleMode = iota
	RULE_MODE_PERMANENT
	RULE_MODE_SYSTEM
)

type Rule struct {
	id       uint
	policy   *Policy
	mode     RuleMode
	rtype    int
	hostname string
	addr     uint32
	port     uint16
}

func (r *Rule) String() string {
	return r.getString(false)
}

func (r *Rule) getString(redact bool) string {
	rtype := "DENY"
	if r.rtype == RULE_ALLOW {
		rtype = "ALLOW"
	}
	rmode := ""
	if r.mode == RULE_MODE_SYSTEM {
		rmode = "|SYSTEM"
	}

	return fmt.Sprintf("%s|%s%s", rtype, r.AddrString(redact), rmode)
}

func (r *Rule) AddrString(redact bool) string {
	addr := "*"
	port := "*"
	if r.hostname != "" {
		addr = r.hostname
	} else if r.addr != matchAny && r.addr != noAddress {
		bs := make([]byte, 4)
		binary.BigEndian.PutUint32(bs, r.addr)
		addr = fmt.Sprintf("%d.%d.%d.%d", bs[0], bs[1], bs[2], bs[3])
	}

	if r.port != matchAny {
		port = fmt.Sprintf("%d", r.port)
	}

	if redact && addr != "*" {
		addr = "[redacted]"
	}

	return fmt.Sprintf("%s:%s", addr, port)
}

type RuleList []*Rule

func (r *Rule) match(dst net.IP, dstPort uint16, hostname string) bool {
	if r.port != matchAny && r.port != dstPort {
		return false
	}
	if r.addr == matchAny {
		return true
	}
	if r.hostname != "" {
		return r.hostname == hostname
	}
	return r.addr == binary.BigEndian.Uint32(dst)
}

type FilterResult int

const (
	FILTER_DENY FilterResult = iota
	FILTER_ALLOW
	FILTER_PROMPT
)

func (rl *RuleList) filterPacket(p *nfqueue.Packet, pinfo *procsnitch.Info, hostname string) FilterResult {
	return rl.filter(p, p.Dst, p.DstPort, hostname, pinfo)
}

func (rl *RuleList) filter(pkt *nfqueue.Packet, dst net.IP, dstPort uint16, hostname string, pinfo *procsnitch.Info) FilterResult {
	if rl == nil {
		return FILTER_PROMPT
	}
	result := FILTER_PROMPT
	for _, r := range *rl {
		if r.match(dst, dstPort, hostname) {
			dstStr := dst.String()
			if FirewallConfig.LogRedact {
				dstStr = "[redacted]"
			}
			srcStr := "[uknown]"
			if pkt != nil {
				srcStr = fmt.Sprintf("%s:%d", pkt.Src, pkt.SrcPort)
			}
			log.Noticef("%s > %s %s %s -> %s:%d",
				r.getString(FirewallConfig.LogRedact),
				pinfo.ExePath, "TCP",
				srcStr,
				dstStr, dstPort)
			if r.rtype == RULE_DENY {
				return FILTER_DENY
			} else if r.rtype == RULE_ALLOW {
				result = FILTER_ALLOW
			}
		}
	}
	return result
}

func parseError(s string) error {
	return fmt.Errorf("unable to parse rule string: %s", s)
}

func (r *Rule) parse(s string) bool {
	r.addr = noAddress
	parts := strings.Split(s, "|")
	if len(parts) < 2 {
		return false
	}
	if len(parts) >= 3 && parts[2] == "SYSTEM" {
		r.mode = RULE_MODE_SYSTEM
	}
	return r.parseVerb(parts[0]) && r.parseTarget(parts[1])
}

func (r *Rule) parseVerb(v string) bool {
	switch v {
	case "ALLOW":
		r.rtype = RULE_ALLOW
		return true
	case "DENY":
		r.rtype = RULE_DENY
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
	ip := net.ParseIP(a)
	if ip == nil {
		return false
	}
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
