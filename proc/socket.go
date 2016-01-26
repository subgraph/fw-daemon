package proc
import (
	"net"
	"fmt"
	"io/ioutil"
	"strings"
	"errors"
	"strconv"
)

type socketAddr struct {
	ip net.IP
	port uint16
}

func (sa socketAddr) String() string {
	return fmt.Sprintf("%v:%d", sa.ip, sa.port)
}

type socketStatus struct {
	local socketAddr
	remote socketAddr
	uid int
	inode uint64
	line string
}

func (ss *socketStatus) String() string {
	return fmt.Sprintf("%s -> %s uid=%d inode=%d", ss.local, ss.remote, ss.uid, ss.inode)
}

func findUDPSocket(srcPort uint16, dstAddr net.IP, dstPort uint16) *socketStatus {
	return findSocket("udp", srcPort, dstAddr, dstPort)
}

func findTCPSocket(srcPort uint16, dstAddr net.IP, dstPort uint16) *socketStatus {
	return findSocket("tcp", srcPort, dstAddr, dstPort)
}

func findSocket(proto string, srcPort uint16, dstAddr net.IP, dstPort uint16) *socketStatus {
	var ss socketStatus
	for _,line := range getSocketLines(proto) {
		if len(line) == 0 {
			continue
		}
		if err := ss.parseLine(line); err != nil {
			log.Warning("Unable to parse line from /proc/net/%s [%s]: %v", proto, line, err)
			continue
		}
		if ss.remote.port == dstPort && ss.remote.ip.Equal(dstAddr) && ss.local.port == srcPort {
			ss.line = line
			return &ss
		}
	}
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
