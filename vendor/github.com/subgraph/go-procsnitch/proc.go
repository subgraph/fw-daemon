package procsnitch

import (
	"encoding/hex"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/op/go-logging"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"unsafe"
)

var log = logging.MustGetLogger("go-procsockets")
var isLittleEndian = -1

// SetLogger allows setting a custom go-logging instance
func SetLogger(logger *logging.Logger) {
	log = logger
}

var pcache = &pidCache{}

// ProcInfo represents an api that can be used to query process information about
// the far side of a network connection
// Note: this can aid in the construction of unit tests.
type ProcInfo interface {
	LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *Info
	LookupUNIXSocketProcess(socketFile string) *Info
	LookupUDPSocketProcess(srcPort uint16) *Info
}

// SystemProcInfo represents our real system ProcInfo api.
type SystemProcInfo struct {
}

// LookupTCPSocketProcess returns the process information for a given TCP connection.
func (r SystemProcInfo) LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *Info {
	return LookupTCPSocketProcess(srcPort, dstAddr, dstPort)
}

// LookupUNIXSocketProcess returns the process information for a given UNIX socket connection.
func (r SystemProcInfo) LookupUNIXSocketProcess(socketFile string) *Info {
	return LookupUNIXSocketProcess(socketFile)
}

// LookupUDPSocketProcess returns the process information for a given UDP socket connection.
func (r SystemProcInfo) LookupUDPSocketProcess(srcPort uint16) *Info {
	return LookupUDPSocketProcess(srcPort)
}

// FindProcessForConnection returns the process information for a given connection.
// So far only TCP and UNIX domain socket connections are supported.
func FindProcessForConnection(conn net.Conn, procInfo ProcInfo) *Info {
	var info *Info
	if conn.LocalAddr().Network() == "tcp" {
		fields := strings.Split(conn.RemoteAddr().String(), ":")
		dstPortStr := fields[1]
		fields = strings.Split(conn.LocalAddr().String(), ":")
		dstIP := net.ParseIP(fields[0])
		srcP, _ := strconv.ParseUint(dstPortStr, 10, 16)
		dstP, _ := strconv.ParseUint(fields[1], 10, 16)
		info = procInfo.LookupTCPSocketProcess(uint16(srcP), dstIP, uint16(dstP))
	} else if conn.LocalAddr().Network() == "unix" {
		info = procInfo.LookupUNIXSocketProcess(conn.LocalAddr().String())
	}
	return info
}

// LookupICMPSocketProcessAll searches for a ICMP socket a given source host, destination IP, and type
func LookupICMPSocketProcessAll(srcAddr net.IP, dstAddr net.IP, code int, custdata []string) *Info {
	ss := findICMPSocketAll(srcAddr, dstAddr, code, custdata)
	if ss == nil {
		return nil
	}
	return pcache.lookup(ss.inode)
}

// LookupUDPSocketProcessAll searches for a UDP socket a given source port, destination IP, and destination port - AND source destination
func LookupUDPSocketProcessAll(srcAddr net.IP, srcPort uint16, dstAddr net.IP, dstPort uint16, custdata []string, strictness int) *Info {
	ss := findUDPSocketAll(srcAddr, srcPort, dstAddr, dstPort, custdata, strictness)
	if ss == nil {
		return nil
	}
	return pcache.lookup(ss.inode)
}

// LookupUDPSocketProcess searches for a UDP socket with a source port
func LookupUDPSocketProcess(srcPort uint16) *Info {
	ss := findUDPSocket(srcPort)
	if ss == nil {
		return nil
	}
	return pcache.lookup(ss.inode)
}

// LookupTCPSocketProcessAll searches for a TCP socket a given source port, destination IP, and destination port - AND source destination
func LookupTCPSocketProcessAll(srcAddr net.IP, srcPort uint16, dstAddr net.IP, dstPort uint16, custdata []string) *Info {
	ss := findTCPSocketAll(srcAddr, srcPort, dstAddr, dstPort, custdata)
	if ss == nil {
		return nil
	}
	return pcache.lookup(ss.inode)
}

// LookupTCPSocketProcess searches for a TCP socket with a given source port, destination IP, and destination port
func LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *Info {
	ss := findTCPSocket(srcPort, dstAddr, dstPort)
	if ss == nil {
		return nil
	}
	return pcache.lookup(ss.inode)
}

// LookupUNIXSocketProcess searches for a UNIX domain socket with a given filename
func LookupUNIXSocketProcess(socketFile string) *Info {
	ss := findUNIXSocket(socketFile)
	if ss == nil {
		return nil
	}
	return pcache.lookup(ss.inode)
}

type connectionInfo struct {
	pinfo  *Info
	local  *socketAddr
	remote *socketAddr
}

func (ci *connectionInfo) String() string {
	return fmt.Sprintf("%v %s %s", ci.pinfo, ci.local, ci.remote)
}

func (sa *socketAddr) parse(s string) error {
	ipPort := strings.Split(s, ":")
	if len(ipPort) != 2 {
		return fmt.Errorf("badly formatted socket address field: %s", s)
	}
	ip, err := ParseIP(ipPort[0])
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

// ParseIP parses a string ip to a net.IP
func ParseIP(ip string) (net.IP, error) {
	var result net.IP
	dst, err := hex.DecodeString(ip)
	if err != nil {
		return result, fmt.Errorf("Error parsing IP: %s", err)
	}
	// Reverse byte order -- /proc/net/tcp etc. is little-endian
	// TODO: Does this vary by architecture?
	if isLittleEndian == -1 {
		setEndian()
	}

	if len(dst) != 4 && len(dst) != 16 {
		return result, errors.New("Unsupported address type (not IPv4 or IPv16)")
	}

	if isLittleEndian > 0 {
		for i := 0; i < len(dst) / 4; i++ {
			start, end := i*4, (i+1)*4
			word := dst[start:end]
			lval := binary.LittleEndian.Uint32(word)
			binary.BigEndian.PutUint32(dst[start:], lval)
		}
	}

/*		if len(dst) == 16 {
			dst2 := []byte{dst[3], dst[2], dst[1], dst[0], dst[7], dst[6], dst[5], dst[4], dst[11], dst[10], dst[9], dst[8], dst[15], dst[14], dst[13], dst[12]}
			return net.IP(dst2), nil
		}
		for i, j := 0, len(dst)-1; i < j; i, j = i+1, j-1 {
			dst[i], dst[j] = dst[j], dst[i]
		} */

	return net.IP(dst), nil
}

// ParsePort parses a base16 port represented as a string to a uint16
func ParsePort(port string) (uint16, error) {
	p64, err := strconv.ParseInt(port, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("Error parsing port: %s", err)
	}
	return uint16(p64), nil
}

func getConnections() ([]*connectionInfo, error) {
	conns, err := readConntrack()
	if err != nil {
		return nil, err
	}
	resolveProcinfo(conns)
	return conns, nil
}

func resolveProcinfo(conns []*connectionInfo) {
	var sockets []*socketStatus
	for _, line := range getSocketLines("tcp") {
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}
		ss := new(socketStatus)
		if err := ss.parseLine(line); err != nil {
			log.Warningf("Unable to parse line [%s]: %v", line, err)
		} /* else {
			/*
				pid := findPidForInode(ss.inode)
				if pid > 0 {
					ss.pid = pid
					fmt.Println("Socket", ss)
					sockets = append(sockets, ss)
				}

		}*/
	}
	for _, ci := range conns {
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

func findContrackSocket(ci *connectionInfo, sockets []*socketStatus) *socketStatus {
	for _, ss := range sockets {
		if ss.local.port == ci.local.port && ss.remote.ip.Equal(ci.remote.ip) && ss.remote.port == ci.remote.port {
			return ss
		}
	}
	return nil
}

func readConntrack() ([]*connectionInfo, error) {
	path := fmt.Sprintf("/proc/net/ip_conntrack")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result []*connectionInfo
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		ci, err := parseConntrackLine(line)
		if err != nil {
			return nil, err
		}
		if ci != nil {
			result = append(result, ci)
		}
	}
	return result, nil
}

func parseConntrackLine(line string) (*connectionInfo, error) {
	parts := strings.Fields(line)
	if len(parts) < 8 || parts[0] != "tcp" || parts[3] != "ESTABLISHED" {
		return nil, nil
	}

	local, err := conntrackAddr(parts[4], parts[6])
	if err != nil {
		return nil, err
	}
	remote, err := conntrackAddr(parts[5], parts[7])
	if err != nil {
		return nil, err
	}
	return &connectionInfo{
		local:  local,
		remote: remote,
	}, nil
}

func conntrackAddr(ipStr, portStr string) (*socketAddr, error) {
	ip := net.ParseIP(stripLabel(ipStr))
	if ip == nil {
		return nil, errors.New("Could not parse IP: " + ipStr)
	}
	i64, err := strconv.Atoi(stripLabel(portStr))
	if err != nil {
		return nil, err
	}
	return &socketAddr{
		ip:   ip,
		port: uint16(i64),
	}, nil
}

func stripLabel(s string) string {
	idx := strings.Index(s, "=")
	if idx == -1 {
		return s
	}
	return s[idx+1:]
}

// stolen from github.com/virtao/GoEndian
const INT_SIZE int = int(unsafe.Sizeof(0))
func setEndian() {
	var i int = 0x1
	bs := (*[INT_SIZE]byte)(unsafe.Pointer(&i))
	if bs[0] == 0 {
		isLittleEndian = 0
	} else {
		isLittleEndian = 1
	}
}
