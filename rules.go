package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/subgraph/fw-daemon/nfqueue"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
)

const (
	RULE_DENY = iota
	RULE_ALLOW
)

const matchAny = 0
const noAddress = uint32(0xffffffff)

type Rule struct {
	sessionOnly bool
	rtype       int
	hostname    string
	addr        uint32
	port        uint16
}

func (r *Rule) String() string {
	addr := "*"
	port := "*"
	rtype := "DENY"

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

	if r.rtype == RULE_ALLOW {
		rtype = "ALLOW"
	}

	return fmt.Sprintf("%s %s:%s", rtype, addr, port)
}

type RuleList []*Rule

func (r *Rule) match(pkt *nfqueue.Packet, name string) bool {
	if r.port != matchAny && r.port != pkt.DstPort {
		return false
	}
	if r.addr == matchAny {
		return true
	}
	if r.hostname != "" {
		return r.hostname == name
	}
	return r.addr == binary.BigEndian.Uint32(pkt.Dst)
}

type FilterResult int

const (
	FILTER_DENY FilterResult = iota
	FILTER_ALLOW
	FILTER_PROMPT
)

func (rl *RuleList) filter(p *nfqueue.Packet, proc *ProcInfo, hostname string) FilterResult {
	if rl == nil {
		return FILTER_PROMPT
	}
	result := FILTER_PROMPT
	for _, r := range *rl {
		if r.match(p, hostname) {
			log.Info("%s (%s -> %s:%d)", r, proc.exePath, p.Dst.String(), p.DstPort)
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
	if len(parts) != 2 {
		return false
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
	if ip == nil || len(ip) != 4 {
		return false
	}
	r.addr = binary.BigEndian.Uint32(ip)
	return true
}

func (r *Rule) parsePort(p string) bool {
	if p == "*" {
		r.port = matchAny
		return true
	}
	var err error
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return false
	}
	r.port = uint16(port)
	return true
}

func parseRule(s string) (*Rule, error) {
	r := new(Rule)
	if !r.parse(s) {
		return nil, parseError(s)
	}
	return r, nil
}

const ruleFile = ".sgfw_rules"

func rulesPath() string {
	home := os.Getenv("HOME")
	if home != "" {
		return filepath.Join(home, ruleFile)
	}
	// XXX try something else?
	return ""
}

func (fw *Firewall) saveRules() {
	fw.lock.Lock()
	defer fw.lock.Unlock()

	f, err := os.Create(rulesPath())
	if err != nil {
		log.Warning("Failed to open %s for writing: %v", rulesPath(), err)
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
		if !r.sessionOnly {
			if !writeLine(f, r.String()) {
				return
			}
		}
	}
}

func writeLine(f *os.File, line string) bool {
	_, err := f.WriteString(line + "\n")
	if err != nil {
		log.Warning("Error writing to rule file: %v", err)
		return false
	}
	return true
}

func (fw *Firewall) loadRules() {
	fw.lock.Lock()
	defer fw.lock.Unlock()

	bs, err := ioutil.ReadFile(rulesPath())
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warning("Failed to open %s for reading: %v", rulesPath(), err)
		}
		return
	}
	var policy *Policy
	for _, line := range strings.Split(string(bs), "\n") {
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			policy = fw.processPathLine(line)
		} else {
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
		log.Warning("Cannot process rule line without first seeing path line: %s", line)
		return
	}
	rule, err := parseRule(line)
	if err != nil {
		log.Warning("Error parsing rule (%s): %v", line, err)
		return
	}
	policy.lock.Lock()
	defer policy.lock.Unlock()
	policy.rules = append(policy.rules, rule)
}
