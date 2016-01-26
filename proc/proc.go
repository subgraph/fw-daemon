package proc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"github.com/subgraph/fw-daemon/Godeps/_workspace/src/github.com/op/go-logging"
)

var log = logging.MustGetLogger("proc")
func SetLogger(logger *logging.Logger) {
	log = logger
}

var pcache = &pidCache{}


func LookupUDPSocketProcess(srcPort uint16) *ProcInfo {
	ss := findUDPSocket(srcPort)
	if ss == nil {
		return nil
	}
	return pcache.lookup(ss.inode)
}

func LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *ProcInfo {
	ss := findTCPSocket(srcPort, dstAddr, dstPort)
	if ss == nil {
		return nil
	}
	return pcache.lookup(ss.inode)
}

type ConnectionInfo struct {
	pinfo *ProcInfo
	local *socketAddr
	remote *socketAddr
}

func (ci *ConnectionInfo) String() string {
	return fmt.Sprintf("%v %s %s", ci.pinfo, ci.local, ci.remote)
}

func (sa *socketAddr) parse(s string) error {
	ipPort := strings.Split(s, ":")
	if len(ipPort) != 2 {
		return fmt.Errorf("badly formatted socket address field: %s", s)
	}
	ip, err := ParseIp(ipPort[0])
	if err != nil {
		return fmt.Errorf("error parsing ip field [%s]: %v", ipPort[0], err)
	}
	port, err := ParsePort(ipPort[1])
	if err != nil {
		return fmt.Errorf("error parsing port field [%s]: %v", ipPort[1], err)
	}
	sa.ip = ip
	sa.port = port
	return nil
}


func ParseIp(ip string) (net.IP, error) {
	var result net.IP
	dst, err := hex.DecodeString(ip)
	if err != nil {
		return result, fmt.Errorf("Error parsing IP: %s", err)
	}
	// Reverse byte order -- /proc/net/tcp etc. is little-endian
	// TODO: Does this vary by architecture?
	for i, j := 0, len(dst)-1; i < j; i, j = i+1, j-1 {
		dst[i], dst[j] = dst[j], dst[i]
	}
	result = net.IP(dst)
	return result, nil
}

func ParsePort(port string) (uint16, error) {
	p64, err := strconv.ParseInt(port, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("Error parsing port: %s", err)
	}
	return uint16(p64), nil
}

func getConnections() ([]*ConnectionInfo, error) {
	conns,err := readConntrack()
	if err != nil {
		return nil, err
	}
	resolveProcinfo(conns)
	return conns, nil
}

func resolveProcinfo(conns []*ConnectionInfo) {
	var sockets []*socketStatus
	for _,line := range getSocketLines("tcp") {
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}
		ss := new(socketStatus)
		if err := ss.parseLine(line); err != nil {
			log.Warning("Unable to parse line [%s]: %v", line, err)
		} else {
			/*
			pid := findPidForInode(ss.inode)
			if pid > 0 {
				ss.pid = pid
				fmt.Println("Socket", ss)
				sockets = append(sockets, ss)
			}
			*/
		}
	}
	for _,ci := range conns {
		ss := findContrackSocket(ci, sockets)
		if ss == nil {
			continue
		}
		pinfo := pcache.lookup(ss.inode)
		if pinfo != nil {
			ci.pinfo = pinfo
		}
	}
}

func findContrackSocket(ci *ConnectionInfo, sockets []*socketStatus) *socketStatus {
	for _,ss := range sockets {
		if ss.local.port == ci.local.port && ss.remote.ip.Equal(ci.remote.ip) && ss.remote.port == ci.remote.port {
			return ss
		}
	}
	return nil
}

func readConntrack() ([]*ConnectionInfo, error) {
	path := fmt.Sprintf("/proc/net/ip_conntrack")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result []*ConnectionInfo
	lines := strings.Split(string(data), "\n")
	for _,line := range(lines) {
		ci,err := parseConntrackLine(line)
		if err != nil {
			return nil, err
		}
		if ci != nil {
			result = append(result, ci)
		}
	}
	return result, nil
}

func parseConntrackLine(line string) (*ConnectionInfo, error) {
	parts := strings.Fields(line)
	if len(parts) < 8 || parts[0] != "tcp" || parts[3] != "ESTABLISHED" {
		return nil, nil
	}

	local,err := conntrackAddr(parts[4], parts[6])
	if err != nil {
		return nil, err
	}
	remote,err := conntrackAddr(parts[5], parts[7])
	if err != nil {
		return nil, err
	}
	return &ConnectionInfo{
		local: local,
		remote: remote,
	},nil
}

func conntrackAddr(ip_str, port_str string) (*socketAddr, error) {
	ip := net.ParseIP(stripLabel(ip_str))
	if ip == nil {
		return nil, errors.New("Could not parse IP: "+ip_str)
	}
	i64, err := strconv.Atoi(stripLabel(port_str))
	if err != nil {
		return nil, err
	}
	return &socketAddr{
		ip: ip,
		port: uint16(i64),
	},nil
}

func stripLabel(s string) string {
	idx := strings.Index(s, "=")
	if idx == -1 {
		return s
	}
	return s[idx+1:]
}
