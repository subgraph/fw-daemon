package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/subgraph/fw-daemon/nfqueue"
)

type ProcInfo struct {
	pid     int
	uid     int
	exePath string
	cmdLine string
}

type socketAddr struct {
	ip   net.IP
	port uint16
}

type socketStatus struct {
	local  socketAddr
	remote socketAddr
	uid    int
	inode  uint64
	pid    int
}

func findProcessForPacket(pkt *nfqueue.Packet) *ProcInfo {
	ss := getSocketForPacket(pkt)
	if ss == nil {
		return nil
	}
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ss.pid))
	if err != nil {
		log.Warning("Error reading exe link for pid %d: %v", ss.pid, err)
		return nil
	}
	bs, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ss.pid))
	if err != nil {
		log.Warning("Error reading cmdline for pid %d: %v", ss.pid, err)
		return nil
	}
	for i, b := range bs {
		if b == 0 {
			bs[i] = byte(' ')
		}
	}

	finfo, err := os.Stat(fmt.Sprintf("/proc/%d", ss.pid))
	if err != nil {
		log.Warning("Could not stat /proc/%d: %v", ss.pid, err)
		return nil
	}
	finfo.Sys()
	return &ProcInfo{
		pid:     ss.pid,
		uid:     ss.uid,
		exePath: exePath,
		cmdLine: string(bs),
	}
}

func getSocketLinesForPacket(pkt *nfqueue.Packet) []string {
	if pkt.Protocol == nfqueue.TCP {
		return getSocketLines("tcp")
	} else if pkt.Protocol == nfqueue.UDP {
		return getSocketLines("udp")
	} else {
		log.Warning("Cannot lookup socket for protocol %s", pkt.Protocol)
		return nil
	}
}

func getSocketLines(proto string) []string {
	path := fmt.Sprintf("/proc/net/%s", proto)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Error reading %s: %v", path, err)
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 {
		lines = lines[1:]
	}
	return lines
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

func (ss *socketStatus) parseLine(line string) error {
	fs := strings.Fields(line)
	if len(fs) < 10 {
		return errors.New("insufficient fields")
	}
	if err := ss.local.parse(fs[1]); err != nil {
		return err
	}
	if err := ss.remote.parse(fs[2]); err != nil {
		return err
	}
	uid, err := strconv.ParseUint(fs[7], 10, 32)
	if err != nil {
		return err
	}
	ss.uid = int(uid)
	inode, err := strconv.ParseUint(fs[9], 10, 64)
	if err != nil {
		return err
	}
	ss.inode = inode
	return nil
}

func getSocketForPacket(pkt *nfqueue.Packet) *socketStatus {
	ss := findSocket(pkt)
	if ss == nil {
		return nil
	}
	pid := findPidForInode(ss.inode)
	if pid == -1 {
		return nil
	}
	ss.pid = pid
	return ss
}

func findSocket(pkt *nfqueue.Packet) *socketStatus {
	var status socketStatus
	for _, line := range getSocketLinesForPacket(pkt) {
		if err := status.parseLine(line); err != nil {
			log.Warning("Unable to parse line [%s]: %v", line, err)
		} else {
			if status.remote.ip.Equal(pkt.Dst) && status.remote.port == pkt.DstPort {
				return &status
			}
		}
	}
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

func findPidForInode(inode uint64) int {
	search := fmt.Sprintf("socket:[%d]", inode)
	for _, pid := range getAllPids() {
		if matchesSocketLink(pid, search) {
			return pid
		}
	}
	return -1
}

func matchesSocketLink(pid int, search string) bool {
	paths, _ := filepath.Glob(fmt.Sprintf("/proc/%d/fd/*", pid))
	for _, p := range paths {
		link, err := os.Readlink(p)
		if err == nil && link == search {
			return true
		}
	}
	return false
}

func getAllPids() []int {
	var pids []int
	d, err := os.Open("/proc")
	if err != nil {
		log.Warning("Error opening /proc: %v", err)
		return nil
	}
	names, err := d.Readdirnames(0)
	if err != nil {
		log.Warning("Error reading directory names from /proc: %v", err)
		return nil
	}
	for _, n := range names {
		if pid, err := strconv.ParseUint(n, 10, 32); err == nil {
			pids = append(pids, int(pid))
		}
	}
	return pids
}
