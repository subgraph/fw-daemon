package nfqueue

import (
	"fmt"
	"net"
	"syscall"
)

type (
	IPVersion  uint8
	IPProtocol uint8
	Verdict    uint8
)

const (
	IPv4 = IPVersion(4)
	IPv6 = IPVersion(6)

	//convience really
	IGMP   = IPProtocol(syscall.IPPROTO_IGMP)
	RAW    = IPProtocol(syscall.IPPROTO_RAW)
	TCP    = IPProtocol(syscall.IPPROTO_TCP)
	UDP    = IPProtocol(syscall.IPPROTO_UDP)
	ICMP   = IPProtocol(syscall.IPPROTO_ICMP)
	ICMPv6 = IPProtocol(syscall.IPPROTO_ICMPV6)
)

const (
	DROP Verdict = iota
	ACCEPT
	STOLEN
	QUEUE
	REPEAT
	STOP
)

var (
	ErrVerdictSentOrTimedOut error = fmt.Errorf("The verdict was already sent or timed out.")
)

func (v IPVersion) String() string {
	switch v {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	}
	return fmt.Sprintf("<unknown ip version, %d>", uint8(v))
}

// Returns the byte size of the ip, IPv4 = 4 bytes, IPv6 = 16
func (v IPVersion) Size() int {
	switch v {
	case IPv4:
		return 4
	case IPv6:
		return 16
	}
	return 0
}

func (p IPProtocol) String() string {
	switch p {
	case RAW:
		return "RAW"
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case ICMP:
		return "ICMP"
	case ICMPv6:
		return "ICMPv6"
	case IGMP:
		return "IGMP"
	}
	return fmt.Sprintf("<unknown protocol, %d>", uint8(p))
}

func (v Verdict) String() string {
	switch v {
	case DROP:
		return "DROP"
	case ACCEPT:
		return "ACCEPT"
	}
	return fmt.Sprintf("<unsupported verdict, %d>", uint8(v))
}

type IPHeader struct {
	Version IPVersion

	Tos, TTL uint8
	Protocol IPProtocol
	Src, Dst net.IP
}

type TCPUDPHeader struct {
	SrcPort, DstPort uint16
	Checksum         uint16 //not implemented
}

// TODO handle other protocols

type Packet struct {
	QueueId    uint16
	Id         uint32
	HWProtocol uint16
	Hook       uint8
	Mark       uint32
	Payload    []byte
	*IPHeader
	*TCPUDPHeader

	verdict chan uint32
}

func (pkt *Packet) String() string {
	return fmt.Sprintf("<Packet QId: %d, Id: %d, Type: %s, Src: %s:%d, Dst: %s:%d, Mark: 0x%X, Checksum: 0x%X, TOS: 0x%X, TTL: %d>",
		pkt.QueueId, pkt.Id, pkt.Protocol, pkt.Src, pkt.SrcPort, pkt.Dst, pkt.DstPort, pkt.Mark, pkt.Checksum, pkt.Tos, pkt.TTL)
}

func (pkt *Packet) setVerdict(v Verdict) (err error) {
	defer func() {
		if x := recover(); x != nil {
			err = ErrVerdictSentOrTimedOut
		}
	}()
	pkt.verdict <- uint32(v)
	close(pkt.verdict)
	return err
}

func (pkt *Packet) Accept() error {
	return pkt.setVerdict(ACCEPT)
}

func (pkt *Packet) Drop() error {
	return pkt.setVerdict(DROP)
}

//HUGE warning, if the iptables rules aren't set correctly this can cause some problems.
// func (pkt *Packet) Repeat() error {
// 	return this.SetVerdict(REPEAT)
// }
