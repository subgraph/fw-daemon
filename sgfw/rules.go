package sgfw

import (
	//	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	nfqueue "github.com/subgraph/go-nfnetlink/nfqueue"
	//	"github.com/subgraph/go-nfnetlink"
	"github.com/subgraph/go-procsnitch"
)

const matchAny = 0

//const noAddress = uint32(0xffffffff)
var anyAddress net.IP = net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var noAddress net.IP = net.IP{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type Rule struct {
	id       uint
	policy   *Policy
	mode     RuleMode
	rtype    RuleAction
	proto    string
	pid      int
	hostname string
	network  *net.IPNet
	addr     net.IP
	saddr    net.IP
	port     uint16
	uid      int
	gid      int
	uname    string
	gname    string
	sandbox  string
}

func (r *Rule) String() string {
	return r.getString(false)
}

func (r *Rule) getString(redact bool) string {
	rtype := RuleActionString[RULE_ACTION_DENY]
	if r.rtype == RULE_ACTION_ALLOW {
		rtype = RuleActionString[RULE_ACTION_ALLOW]
	} else if r.rtype == RULE_ACTION_ALLOW_TLSONLY {
		rtype = RuleActionString[RULE_ACTION_ALLOW_TLSONLY]
	}
	rmode := ""
	if r.mode == RULE_MODE_SYSTEM {
		rmode = "|" + RuleModeString[RULE_MODE_SYSTEM]
	}
	if r.mode == RULE_MODE_PERMANENT {
		rmode = "|" + RuleModeString[RULE_MODE_PERMANENT]
	}

	protostr := ""

	if r.proto != "tcp" {
		protostr = r.proto + ":"
	}

	rpriv := fmt.Sprintf("|%d:%d", r.uid, r.gid)

	sbox := "|"
	if r.sandbox != "" {
		sbox = "|" + sbox
	}

	return fmt.Sprintf("%s|%s%s%s%s%s", rtype, protostr, r.AddrString(redact), rmode, rpriv, sbox)
}

func (r *Rule) AddrString(redact bool) string {
	addr := "*"
	port := "*"
	if r.hostname != "" {
		addr = r.hostname
	} else if r.network != nil {
		addr = r.network.String()
	} else if !addrMatchesAny(r.addr) && !addrMatchesNone(r.addr) {
		//		bs := make([]byte, 4)
		//		binary.BigEndian.PutUint32(bs, r.addr)
		//		addr = fmt.Sprintf("%d.%d.%d.%d", bs[0], bs[1], bs[2], bs[3])
		addr = r.addr.String()
	}

	if r.port != matchAny || r.proto == "icmp" {
		port = fmt.Sprintf("%d", r.port)
	}

	if redact && addr != "*" {
		addr = STR_REDACTED
	}

	return fmt.Sprintf("%s:%s", addr, port)
}

type RuleList []*Rule

func (r *Rule) match(src net.IP, dst net.IP, dstPort uint16, hostname string, proto string, uid, gid int, uname, gname string) bool {
	if r.proto != proto {
		return false
	}
	if r.uid != -1 && r.uid != uid {
		return false
	} else if r.gid != -1 && r.gid != gid {
		return false
	} else if r.uname != "" && r.uname != uname {
		return false
	} else if r.gname != "" && r.gname != gname {
		return false
	}

	// log.Notice("comparison: ", hostname, " / ", dst, " : ", dstPort, " -> ", r.addr, " / ", r.hostname, " : ", r.port)
	if r.port != matchAny && r.port != dstPort {
		return false
	}
	if addrMatchesAny(r.addr) {
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
	if proto == "icmp" {
		//fmt.Printf("network = %v, src = %v, r.addr = %x, src to4 = %x\n", r.network, src, r.addr, binary.BigEndian.Uint32(src.To4()))
		if (r.network != nil && r.network.Contains(src)) || (r.addr.Equal(src)) {
			return true
		}
	}
	return r.addr.Equal(dst)
}

func (rl *RuleList) filterPacket(p *nfqueue.NFQPacket, pinfo *procsnitch.Info, srcip net.IP, hostname, optstr string) FilterResult {
	_, dstip := getPacketIPAddrs(p)
	_, dstp := getPacketPorts(p)
	return rl.filter(p, srcip, dstip, dstp, hostname, pinfo, optstr)
}

func (rl *RuleList) filter(pkt *nfqueue.NFQPacket, src, dst net.IP, dstPort uint16, hostname string, pinfo *procsnitch.Info, optstr string) FilterResult {
	if rl == nil {
		return FILTER_PROMPT
	}
	result := FILTER_PROMPT
	sandboxed := false
	if pinfo.Sandbox != "" {
		sandboxed = true
	}
	// sandboxed := strings.HasPrefix(optstr, "SOCKS5|Tor / Sandbox")
	for _, r := range *rl {
		nfqproto := ""
		//log.Notice("------------ trying match of src ", src, " against: ", r, " | ", r.saddr, " / optstr = ", optstr, "; pid ", pinfo.Pid, " vs rule pid ", r.pid)
		//log.Notice("r.saddr: ", r.saddr, "src: ", src, "sandboxed ", sandboxed, "optstr: ", optstr)
		if r.saddr == nil && src != nil && sandboxed {
			log.Notice("! Skipping comparison against incompatible rule types: rule src = ", r.saddr, " / packet src = ", src)
			// continue
		} else if r.saddr == nil && src == nil && sandboxed {
			// continue
			// r.match(src, dst, dstPort, hostname, nil, pinfo.UID, pinfo.GID, uidToUser(pinfo.UID), gidToGroup(pinfo.GID))
			nfqproto = "tcp"
		} else if r.saddr != nil && !r.saddr.Equal(src) && r.proto != "icmp" {
			log.Notice("! Skipping comparison of mismatching source ips")
			continue
		} else {
			if pkt != nil {
				nfqproto = getNFQProto(pkt)
			} else {
				if r.saddr == nil && src == nil && sandboxed == false && (r.port == dstPort || r.port == matchAny) && (r.addr.Equal(anyAddress) || r.hostname == "" || r.hostname == hostname) {
					//	log.Notice("+ Socks5 MATCH SUCCEEDED")
					if r.rtype == RULE_ACTION_DENY {
						return FILTER_DENY
					} else if r.rtype == RULE_ACTION_ALLOW {
						return FILTER_ALLOW
					} else if r.rtype == RULE_ACTION_ALLOW_TLSONLY {
						return FILTER_ALLOW_TLSONLY
					}
				} else {
					return FILTER_PROMPT
				}
			}
		}
		// log.Notice("r.saddr = ", r.saddr, "src = ", src, "\n")
		if r.pid >= 0 && r.pid != pinfo.Pid {
			//log.Notice("! Skipping comparison of mismatching PIDs")
			continue
		}
		if r.match(src, dst, dstPort, hostname, nfqproto, pinfo.UID, pinfo.GID, uidToUser(pinfo.UID), gidToGroup(pinfo.GID)) {
			//	log.Notice("+ MATCH SUCCEEDED")
			dstStr := dst.String()
			if FirewallConfig.LogRedact {
				dstStr = STR_REDACTED
			}
			srcStr := STR_UNKNOWN
			if pkt != nil {
				srcip, _ := getPacketIPAddrs(pkt)
				srcp, _ := getPacketPorts(pkt)
				srcStr = fmt.Sprintf("%s:%d", srcip, srcp)
			}
			//	log.Noticef("%s > %s %s %s -> %s:%d",
			//r.getString(FirewallConfig.LogRedact), pinfo.ExePath, r.proto, srcStr, dstStr, dstPort)
			if r.rtype == RULE_ACTION_DENY {
				//TODO: Optionally redact below log entry
				log.Warningf("DENIED outgoing connection attempt by %s from %s %s -> %s:%d",
					pinfo.ExePath, r.proto,
					srcStr,
					dstStr, dstPort)
				return FILTER_DENY
			} else if r.rtype == RULE_ACTION_ALLOW {
				result = FILTER_ALLOW
				return result
				/*
					if r.saddr != nil {
						return result
					}
				*/
			} else if r.rtype == RULE_ACTION_ALLOW_TLSONLY {
				result = FILTER_ALLOW_TLSONLY
				return result
			}
		}
		/**else {
			log.Notice("+ MATCH FAILED")
		} */
	}
	// log.Notice("--- RESULT = ", result)
	return result
}

func parseError(s string) error {
	return fmt.Errorf("unable to parse rule string: %s", s)
}

func (r *Rule) parse(s string) bool {
	r.addr = noAddress
	r.saddr = nil
	parts := strings.Split(s, "|")
	if len(parts) < 4 || len(parts) > 6 {
		log.Notice("invalid number ", len(parts), " of rule parts in line ", s)
		return false
	}
	if parts[2] == "SYSTEM" {
		r.mode = RULE_MODE_SYSTEM
	} else if parts[2] == "PERMANENT" {
		r.mode = RULE_MODE_PERMANENT
	} else if parts[2] != "" {
		log.Notice("invalid rule mode ", parts[2], " in line ", s)
		return false
	}

	if !r.parsePrivs(parts[3]) {
		log.Notice("invalid privs ", parts[3], " in line ", s)
		return false
	}

	if !r.parseSandbox(parts[4]) {
		log.Notice("invalid sandbox ", parts[4], "in line ", s)
		return false
	}

	// fmt.Printf("uid = %v, gid = %v, user = %v, group = %v, hostname = %v, sandbox = %v\n", r.uid, r.gid, r.uname, r.gname, r.hostname, r.sandbox)

	if len(parts) == 6 && len(strings.TrimSpace(parts[5])) > 0 {
		r.saddr = net.ParseIP(parts[5])

		if r.saddr == nil {
			log.Notice("invalid source IP ", parts[5], " in line ", s)
			return false
		}

	}
	return r.parseVerb(parts[0]) && r.parseTarget(parts[1])
}

func (r *Rule) parseSandbox(p string) bool {
	r.sandbox = p
	return true
}

func (r *Rule) parsePrivs(p string) bool {
	toks := strings.Split(p, ":")
	if len(toks) > 2 {
		return false
	}
	r.uid, r.gid = -1, -1
	r.uname, r.gname = "", ""
	ustr := toks[0]

	uid, err := strconv.Atoi(ustr)

	if err != nil {
		r.uname = ustr
	} else {
		r.uid = uid
	}

	if len(toks) > 1 {
		gstr := toks[1]

		gid, err := strconv.Atoi(gstr)

		if err != nil {
			r.gname = gstr
		} else {
			r.gid = gid
		}

	}

	return true
}

func (r *Rule) parseVerb(v string) bool {
	switch v {
	case RuleActionString[RULE_ACTION_ALLOW]:
		r.rtype = RULE_ACTION_ALLOW
		return true
	case RuleActionString[RULE_ACTION_ALLOW_TLSONLY]:
		r.rtype = RULE_ACTION_ALLOW_TLSONLY
		return true
	case RuleActionString[RULE_ACTION_DENY]:
		r.rtype = RULE_ACTION_DENY
		return true
	}
	return false
}

func (r *Rule) parseTarget(t string) bool {
	addrPort := strings.Split(t, ":")
	if len(addrPort) < 2 {
		return false
	}
	sind := 0
	lind := len(addrPort) - 1
	if addrPort[0] == "udp" || addrPort[0] == "icmp" || addrPort[0] == "tcp" {
		r.proto = addrPort[0]
		sind++
	} else {
		r.proto = "tcp"
	}

	newAddr := strings.Join(addrPort[sind:lind], ":")
	return r.parseAddr(newAddr) && r.parsePort(addrPort[lind])
	//	return r.parseAddr(addrPort[sind]) && r.parsePort(addrPort[sind+1])
}

func (r *Rule) parseAddr(a string) bool {
	if a == "*" {
		r.hostname = ""
		r.addr = anyAddress
		return true
	}
	//	if strings.IndexFunc(a, unicode.IsLetter) != -1 {
	if net.ParseIP(a) == nil {
		r.hostname = a
		return true
	}
	//	ip := net.ParseIP(a)
	ip, ipnet, err := net.ParseCIDR(a)
	if err != nil || ip == nil {
		ip = net.ParseIP(a)

		if ip == nil {
			return false
		}
	} else {
		r.network = ipnet
	}
	r.addr = ip
	return true
}

func (r *Rule) parsePort(p string) bool {
	if p == "*" {
		r.port = matchAny
		return true
	}
	var err error
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil || (port == 0 && r.proto != "icmp") || port > 0xFFFF {
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
	log.Warningf("p.path: ", p.path)
	if !writeLine(f, "["+p.sandbox+"|"+p.path+"]") {
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
		} else {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 0 && trimmed[:1] != "#" {
				processRuleLine(policy, trimmed)
			}
		}
	}
}

func (fw *Firewall) processPathLine(line string) *Policy {
	pathLine := line[1 : len(line)-1]
	toks := strings.Split(pathLine, "|")
	policy := fw.policyForPathAndSandbox(toks[1], toks[0])
	policy.lock.Lock()
	defer policy.lock.Unlock()
	policy.rules = nil
	return policy
}

func processRuleLine(policy *Policy, line string) {
	if policy == nil {
		log.Warningf("Cannot process rule line without first seeing policy key line: %s", line)
		return
	}
	_, err := policy.parseRule(line, true)
	if err != nil {
		log.Warningf("Error parsing rule (%s): %v", line, err)
		return
	}
}

func addrMatchesAny(addr net.IP) bool {
	any := anyAddress

	if addr.To4() != nil {
		any = net.IP{0, 0, 0, 0}
	}

	return any.Equal(addr)
}

func addrMatchesNone(addr net.IP) bool {
	none := noAddress

	if addr.To4() != nil {
		none = net.IP{0xff, 0xff, 0xff, 0xff}
	}

	return none.Equal(addr)
}
