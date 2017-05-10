package sgfw

import (
	"fmt"
	"strings"
	"strconv"
	"sync"

//	"encoding/binary"

//	nfnetlink "github.com/subgraph/go-nfnetlink"
	nfqueue "github.com/subgraph/go-nfnetlink/nfqueue"
//	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/subgraph/go-procsnitch"
	"net"
	"syscall"
	"unsafe"
	"os"
)

var _interpreters = []string{
	"python",
	"ruby",
	"bash",
}

type sandboxRule struct {
	SrcIf net.IP
	DstIP net.IP
	DstPort uint16
	Whitelist bool
}

var sandboxRules = []sandboxRule {
//	{ net.IP{172,16,1,42}, net.IP{140,211,166,134}, 21, false },
}

type pendingConnection interface {
	policy() *Policy
	procInfo() *procsnitch.Info
	hostname() string
	getOptString() string
	src() net.IP
	srcPort() uint16
	dst() net.IP
	dstPort() uint16
	accept()
	drop()
	print() string
}

type pendingPkt struct {
	pol   *Policy
	name  string
	pkt   *nfqueue.NFQPacket
	pinfo *procsnitch.Info
	optstring string
}

func getEmptyPInfo() *procsnitch.Info {
	pinfo := procsnitch.Info{}
	pinfo.UID, pinfo.Pid, pinfo.ParentPid = -1, -1, -1
	pinfo.ExePath = "[unknown-exe]"
	pinfo.CmdLine = "[unknown-cmdline]"
	pinfo.FirstArg = "[unknown-arg]"
	pinfo.ParentCmdLine = "[unknown-pcmdline]"
	pinfo.ParentExePath = "[unknown-pexe]"
	return &pinfo
}

func (pp *pendingPkt) policy() *Policy {
	return pp.pol
}

func (pp *pendingPkt) procInfo() *procsnitch.Info {
	if pp.pinfo == nil {
		return getEmptyPInfo()
	}

	return pp.pinfo
}

func (pp *pendingPkt) getOptString() string {
	return pp.optstring
}

func (pp *pendingPkt) hostname() string {
	return pp.name
}

func (pp *pendingPkt) src() net.IP {
	src, _ := getPacketIP4Addrs(pp.pkt)
	return src
}

func (pp *pendingPkt) dst() net.IP {
	_, dst := getPacketIP4Addrs(pp.pkt)
	return dst
/*	dst := pp.pkt.Packet.NetworkLayer().NetworkFlow().Dst()

	if dst.EndpointType() != layers.EndpointIPv4 {
		return nil
	}

	return dst.Raw() */
//	pp.pkt.NetworkLayer().Layer
}

func (pp *pendingPkt) srcPort() uint16 {
	srcp, _ := getPacketTCPPorts(pp.pkt)
	return srcp
}

func (pp *pendingPkt) dstPort() uint16 {
/*	dst := pp.pkt.Packet.TransportLayer().TransportFlow().Dst()

	if dst.EndpointType() != layers.EndpointTCPPort {
		return 0
	}

	return binary.BigEndian.Uint16(dst.Raw()) */
	_, dstp := getPacketTCPPorts(pp.pkt)
	return dstp
//	return pp.pkt.DstPort
}

func (pp *pendingPkt) accept() {
	pp.pkt.Accept()
}

func (pp *pendingPkt) drop() {
	pp.pkt.SetMark(1)
	pp.pkt.Accept()
}

func (pp *pendingPkt) print() string {
	return printPacket(pp.pkt, pp.name, pp.pinfo)
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

func (p *Policy) processPacket(pkt *nfqueue.NFQPacket, pinfo *procsnitch.Info, optstr string) {

/*	hbytes, err := pkt.GetHWAddr()
	if err != nil {
		log.Notice("Failed to get HW address underlying packet: ", err)
	} else { log.Notice("got hwaddr: ", hbytes) } */
	p.lock.Lock()
	defer p.lock.Unlock()
	dstb := pkt.Packet.NetworkLayer().NetworkFlow().Dst().Raw()
	dstip := net.IP(dstb)
	srcip := net.IP(pkt.Packet.NetworkLayer().NetworkFlow().Src().Raw())
//	_, dstp := getPacketPorts(pkt)
	name := p.fw.dns.Lookup(dstip)
	if !FirewallConfig.LogRedact {
		log.Infof("Lookup(%s): %s", dstip.String(), name)
	}
//	fwo := matchAgainstOzRules(srcip, dstip, dstp)

if name == "" {
/*	log.Notice("XXXXXXXXXXXXx trying better rev lookup:")
	net.LookupAddr(dstip.String())
	name = p.fw.dns.Lookup(dstip)
	log.Notice("NOW ITS: ", name) */
}

//log.Notice("XXX: Attempting to filter packet on rules -> ", fwo, " / rev lookup = ", name)
	result := p.rules.filterPacket(pkt, pinfo, srcip, name, optstr)
	switch result {
	case FILTER_DENY:
		pkt.SetMark(1)
		pkt.Accept()
	case FILTER_ALLOW:
		pkt.Accept()
	case FILTER_PROMPT:
		p.processPromptResult(&pendingPkt{pol: p, name: name, pkt: pkt, pinfo: pinfo, optstring: optstr})
	default:
		log.Warningf("Unexpected filter result: %d", result)
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

func (p *Policy) processNewRule(r *Rule, scope FilterScope) bool {
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
log.Noticef("XXX: attempt to parse rule: |%s|\n", s)
	r := new(Rule)
	r.mode = RULE_MODE_PERMANENT
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
		if rule.match(pc.src(), pc.dst(), pc.dstPort(), pc.hostname()) {
			log.Infof("Adding rule for: %s", rule.getString(FirewallConfig.LogRedact))
			log.Noticef("%s > %s", rule.getString(FirewallConfig.LogRedact), pc.print())
			if rule.rtype == RULE_ACTION_ALLOW {
				pc.accept()
			} else {
				srcs := pc.src().String() + ":" + strconv.Itoa(int(pc.srcPort()))
				log.Warningf("DENIED outgoing connection attempt by %s from %s %s -> %s:%d (user prompt)",
                                pc.procInfo().ExePath, "TCP", srcs, pc.dst(), pc.dstPort)
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
		if r.mode != RULE_MODE_SESSION {
			return true
		}
	}
	return false
}

func printPacket(pkt *nfqueue.NFQPacket, hostname string, pinfo *procsnitch.Info) string {
	proto := "???"
	SrcPort, DstPort := uint16(0), uint16(0)
	SrcIp, DstIp := getPacketIP4Addrs(pkt)

//	switch pkt.Packet.TransportLayer().TransportFlow().EndpointType() {
	if pkt.Packet.Layer(layers.LayerTypeTCP) != nil {
//		case 4:
		proto = "TCP"
	} else if pkt.Packet.Layer(layers.LayerTypeUDP) != nil {
//		case 5:
		proto = "UDP"
	}

	if proto == "TCP" {
		SrcPort, DstPort = getPacketTCPPorts(pkt)
	} else if proto == "UDP" {
		SrcPort, DstPort = getPacketUDPPorts(pkt)
	}

	if FirewallConfig.LogRedact {
		hostname = STR_REDACTED
	}
	name := hostname
	if name == "" {
		name = DstIp.String()
	}
	if pinfo == nil {
		return fmt.Sprintf("(%s %s:%d -> %s:%d)", proto, SrcIp, SrcPort, name, DstPort)
	}

	return fmt.Sprintf("%s %s %s:%d -> %s:%d", pinfo.ExePath, proto, SrcIp, SrcPort, name, DstPort)
}

func (fw *Firewall) filterPacket(pkt *nfqueue.NFQPacket) {
	if pkt.Packet.Layer(layers.LayerTypeUDP) != nil {
		srcport, _ := getPacketUDPPorts(pkt)

		if srcport == 53 {
			pkt.Accept()
			fw.dns.processDNS(pkt.Packet)
			return
		}

	}
	_, dstip := getPacketIP4Addrs(pkt)
/*	_, dstp := getPacketPorts(pkt)
	fwo := matchAgainstOzRules(srcip, dstip, dstp)
	log.Notice("XXX: Attempting [2] to filter packet on rules -> ", fwo)

	if fwo == OZ_FWRULE_WHITELIST {
		log.Noticef("Automatically passed through whitelisted sandbox traffic from %s to %s:%d\n", srcip, dstip, dstp)
		pkt.Accept()
		return
	} else if fwo == OZ_FWRULE_BLACKLIST {
		log.Noticef("Automatically blocking blacklisted sandbox traffic from %s to %s:%d\n", srcip, dstip, dstp)
		pkt.SetMark(1)
		pkt.Accept()
		return
	} */


	ppath := "*"

	pinfo, optstring := findProcessForPacket(pkt)
	if pinfo == nil {
		pinfo = getEmptyPInfo()
		ppath = "[unknown]"
		optstring = "[Connection could not be mapped]"
		log.Warningf("No proc found for %s", printPacket(pkt, fw.dns.Lookup(dstip), nil))
//		pkt.Accept()
//		return
	} else {
		ppath = pinfo.ExePath
		cf := strings.Fields(pinfo.CmdLine)
		if len(cf) > 1 && strings.HasPrefix(cf[1], "/") {
			for _, intp := range _interpreters {
				if strings.Contains(pinfo.ExePath, intp) {
					ppath = cf[1]
					break
				}
			}
		}
	}
	log.Debugf("filterPacket [%s] %s", ppath, printPacket(pkt, fw.dns.Lookup(dstip), nil))
	if basicAllowPacket(pkt) {
		pkt.Accept()
//log.Notice("XXX: passed basicallowpacket")
		return
	}
	policy := fw.PolicyForPath(ppath)
//log.Notice("XXX: flunked basicallowpacket; policy = ", policy)
	policy.processPacket(pkt, pinfo, optstring)
}

func readFileDirect(filename string) ([]byte, error) {
	bfilename, err := syscall.BytePtrFromString(filename)

	if err != nil {
		return nil, err
	}

	res, _, err := syscall.Syscall(syscall.SYS_OPEN, uintptr(unsafe.Pointer(bfilename)), syscall.O_RDONLY, 0)
	fdlong := int64(res)

	if fdlong < 0 {
		return nil, err
	}

	fd := int(res)
	data := make([]byte, 65535)

	val, err := syscall.Read(fd, data)

	if err != nil {
		return nil, err
	}

	syscall.Close(fd)

	if val < 65535 {
		data = data[0:val]
	}

	return data, nil
}

func getAllProcNetDataLocal() ([]string, error) {
	data := ""

	for i := 0; i < len(OzInitPids); i++ {
		fname := fmt.Sprintf("/proc/%d/net/tcp", OzInitPids[i])
fmt.Println("XXX: opening: ", fname)
		bdata, err := readFileDirect(fname)

		if err != nil {
			fmt.Println("Error reading proc data from ", fname, ": ", err)
		} else {
			data += string(bdata)
		}

	}

	lines := strings.Split(data, "\n")
	rlines := make([]string, 0)
	ctr := 1

	for l := 0; l < len(lines); l++ {
		lines[l] = strings.TrimSpace(lines[l])
		ssplit := strings.Split(lines[l], ":")

		if len(ssplit) != 6 {
			continue
		}

		ssplit[0] = fmt.Sprintf("%d", ctr)
		ctr++
		rlines = append(rlines, strings.Join(ssplit, ":"))
	}

	return rlines, nil
}

func getRealRoot(pathname string, pid int) string {
	pfname := fmt.Sprintf("/proc/%d/root", pid)
	lnk, err := os.Readlink(pfname)

	if err != nil {
		fmt.Printf("Error reading link at %s: %v", pfname, err)
		return pathname
	}

	if strings.HasPrefix(pathname, lnk) {
		return pathname[len(lnk):]
	}

	return pathname
}

func findProcessForPacket(pkt *nfqueue.NFQPacket) (*procsnitch.Info, string) {
	srcip, dstip := getPacketIP4Addrs(pkt)
	srcp, dstp := getPacketPorts(pkt)
	optstr := ""

	if pkt.Packet.Layer(layers.LayerTypeTCP) != nil {
		// Try normal way first, before the more resource intensive/invasive way.
		res := procsnitch.LookupTCPSocketProcessAll(srcip, srcp, dstip, dstp, nil)

		if res == nil {
			removePids := make([]int, 0)

			for i := 0; i < len(OzInitPids); i++ {
				data := ""
				fname := fmt.Sprintf("/proc/%d/net/tcp", OzInitPids[i].Pid)
fmt.Println("XXX: opening: ", fname)
				bdata, err := readFileDirect(fname)

				if err != nil {
					fmt.Println("Error reading proc data from ", fname, ": ", err)

					if err == syscall.ENOENT {
						removePids = append(removePids, OzInitPids[i].Pid)
					}

					continue
				} else {
					data = string(bdata)
					lines := strings.Split(data, "\n")
					rlines := make([]string, 0)

					for l := 0; l < len(lines); l++ {
						lines[l] = strings.TrimSpace(lines[l])
						ssplit := strings.Split(lines[l], ":")

						if len(ssplit) != 6 {
							continue
						}

						rlines = append(rlines, strings.Join(ssplit, ":"))
					}

					res = procsnitch.LookupTCPSocketProcessAll(srcip, srcp, dstip, dstp, rlines)

					if res != nil {
						optstr = "Sandbox: " + OzInitPids[i].Name
						res.ExePath = getRealRoot(res.ExePath, OzInitPids[i].Pid)
						break
					}
				}

			}

			for _, p := range removePids {
				removeInitPid(p)
			}

		}

		return res, optstr
	} else if pkt.Packet.Layer(layers.LayerTypeUDP) != nil {
		return procsnitch.LookupUDPSocketProcess(srcp), optstr
	}

	log.Warningf("Packet has unknown protocol: %d", pkt.Packet.NetworkLayer().LayerType())
	//log.Warningf("Packet has unknown protocol: %d", pkt.Protocol)
	return nil, optstr
}

func basicAllowPacket(pkt *nfqueue.NFQPacket) bool {
	_, dstip := getPacketIP4Addrs(pkt)
	return dstip.IsLoopback() ||
		dstip.IsLinkLocalMulticast() ||
		pkt.Packet.Layer(layers.LayerTypeTCP) == nil
//		pkt.Protocol != nfqueue.TCP
}

func getPacketIP4Addrs(pkt *nfqueue.NFQPacket) (net.IP, net.IP) {
	ipLayer := pkt.Packet.Layer(layers.LayerTypeIPv4)

	if ipLayer == nil {
		return net.IP{0,0,0,0}, net.IP{0,0,0,0}
	}

	ip, _ := ipLayer.(*layers.IPv4)
	return ip.SrcIP, ip.DstIP
}

func getPacketTCPPorts(pkt *nfqueue.NFQPacket) (uint16, uint16) {
	tcpLayer := pkt.Packet.Layer(layers.LayerTypeTCP)

	if tcpLayer == nil {
		return 0, 0
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	return uint16(tcp.SrcPort), uint16(tcp.DstPort)
}

func getPacketUDPPorts(pkt *nfqueue.NFQPacket) (uint16, uint16) {
	udpLayer := pkt.Packet.Layer(layers.LayerTypeUDP)

	if udpLayer == nil {
		return 0, 0
	}

	udp, _ := udpLayer.(*layers.UDP)
	return uint16(udp.SrcPort), uint16(udp.DstPort)
}

func getPacketPorts(pkt *nfqueue.NFQPacket) (uint16, uint16) {
	s, d := getPacketTCPPorts(pkt)

	if s == 0 && d == 0 {
		s, d = getPacketUDPPorts(pkt)
	}

	return s, d
}

/*func matchAgainstOzRules(srci, dsti net.IP, dstp uint16) int {

	for i := 0; i < len(sandboxRules); i++ {

	log.Notice("XXX: Attempting to match: ", srci, " / ", dsti, " / ", dstp, " | ", sandboxRules[i])

		if sandboxRules[i].SrcIf.Equal(srci) && sandboxRules[i].DstIP.Equal(dsti) && sandboxRules[i].DstPort == dstp {
			if sandboxRules[i].Whitelist {
				return OZ_FWRULE_WHITELIST
			}
			return OZ_FWRULE_BLACKLIST
		}

	}

	return OZ_FWRULE_NONE
} */
