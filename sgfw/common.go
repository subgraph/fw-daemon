/*
 * common.go - SOCSK5 common definitons/routines.
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

// Package socks5 implements a SOCKS5 client/server.  For more information see
// RFC 1928 and RFC 1929.
//
// Notes:
//  * GSSAPI authentication, is NOT supported.
//  * The authentication provided by the client is always accepted.
//  * A lot of the code is shamelessly stolen from obfs4proxy.
package sgfw

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"
)

const (
	version = 0x05
	rsv     = 0x00

	atypIPv4       = 0x01
	atypDomainName = 0x03
	atypIPv6       = 0x04

	authNoneRequired        = 0x00
	authUsernamePassword    = 0x02
	authNoAcceptableMethods = 0xff

	inboundTimeout = 5 * time.Second
	requestTimeout = 30 * time.Second
)

var errInvalidAtyp = errors.New("invalid address type")

// ReplyCode is a SOCKS 5 reply code.
type ReplyCode byte

// The various SOCKS 5 reply codes from RFC 1928.
const (
	ReplySucceeded ReplyCode = iota
	ReplyGeneralFailure
	ReplyConnectionNotAllowed
	ReplyNetworkUnreachable
	ReplyHostUnreachable
	ReplyConnectionRefused
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressNotSupported
)

// Command is a SOCKS 5 command.
type Command byte

// The various SOCKS 5 commands.
const (
	CommandConnect       Command = 0x01
	CommandTorResolve    Command = 0xf0
	CommandTorResolvePTR Command = 0xf1
)

// Address is a SOCKS 5 address + port.
type Address struct {
	atyp    uint8
	raw     []byte
	addrStr string
	portStr string
}

// FromString parses the provided "host:port" format address and populates the
// Address fields.
func (addr *Address) FromString(addrStr string) (err error) {
	addr.addrStr, addr.portStr, err = net.SplitHostPort(addrStr)
	if err != nil {
		return
	}

	var raw []byte
	if ip := net.ParseIP(addr.addrStr); ip != nil {
		if v4Addr := ip.To4(); v4Addr != nil {
			raw = append(raw, atypIPv4)
			raw = append(raw, v4Addr...)
		} else if v6Addr := ip.To16(); v6Addr != nil {
			raw = append(raw, atypIPv6)
			raw = append(raw, v6Addr...)
		} else {
			return errors.New("unsupported IP address type")
		}
	} else {
		// Must be a FQDN.
		if len(addr.addrStr) > 255 {
			return fmt.Errorf("invalid FQDN, len > 255 bytes (%d bytes)", len(addr.addrStr))
		}
		raw = append(raw, atypDomainName)
		raw = append(raw, addr.addrStr...)
	}

	var port uint64
	if port, err = strconv.ParseUint(addr.portStr, 10, 16); err != nil {
		return
	}
	raw = append(raw, byte(port>>8))
	raw = append(raw, byte(port&0xff))

	addr.raw = raw
	return
}

// String returns the string representation of the address, in "host:port"
// format.
func (addr *Address) String() string {
	return addr.addrStr + ":" + addr.portStr
}

// HostPort returns the string representation of the addess, split into the
// host and port components.
func (addr *Address) HostPort() (string, string) {
	return addr.addrStr, addr.portStr
}

// Type returns the address type from the connect command this address was
// parsed from
func (addr *Address) Type() uint8 {
	return addr.atyp
}

func (addr *Address) read(conn net.Conn) (err error) {
	// The address looks like:
	//  uint8_t atyp
	//  uint8_t addr[] (Length depends on atyp)
	//  uint16_t port

	// Read the atype.
	var atyp byte
	if atyp, err = readByte(conn); err != nil {
		return
	}
	addr.raw = append(addr.raw, atyp)

	// Read the address.
	var rawAddr []byte
	switch atyp {
	case atypIPv4:
		rawAddr = make([]byte, net.IPv4len)
		if _, err = io.ReadFull(conn, rawAddr); err != nil {
			return
		}
		v4Addr := net.IPv4(rawAddr[0], rawAddr[1], rawAddr[2], rawAddr[3])
		addr.addrStr = v4Addr.String()
	case atypDomainName:
		var alen byte
		if alen, err = readByte(conn); err != nil {
			return
		}
		if alen == 0 {
			return fmt.Errorf("domain name with 0 length")
		}
		rawAddr = make([]byte, alen)
		addr.raw = append(addr.raw, alen)
		if _, err = io.ReadFull(conn, rawAddr); err != nil {
			return
		}
		addr.addrStr = string(rawAddr)
	case atypIPv6:
		rawAddr = make([]byte, net.IPv6len)
		if _, err = io.ReadFull(conn, rawAddr); err != nil {
			return
		}
		v6Addr := make(net.IP, net.IPv6len)
		copy(v6Addr[:], rawAddr)
		addr.addrStr = fmt.Sprintf("[%s]", v6Addr.String())
	default:
		return errInvalidAtyp
	}
	addr.atyp = atyp
	addr.raw = append(addr.raw, rawAddr...)

	// Read the port.
	var rawPort [2]byte
	if _, err = io.ReadFull(conn, rawPort[:]); err != nil {
		return
	}
	port := int(rawPort[0])<<8 | int(rawPort[1])
	addr.portStr = fmt.Sprintf("%d", port)
	addr.raw = append(addr.raw, rawPort[:]...)

	return
}

// ErrorToReplyCode converts an error to the "best" reply code.
func ErrorToReplyCode(err error) ReplyCode {
	if cErr, ok := err.(clientError); ok {
		return ReplyCode(cErr)
	}
	opErr, ok := err.(*net.OpError)
	if !ok {
		return ReplyGeneralFailure
	}

	errno, ok := opErr.Err.(syscall.Errno)
	if !ok {
		return ReplyGeneralFailure
	}
	switch errno {
	case syscall.EADDRNOTAVAIL:
		return ReplyAddressNotSupported
	case syscall.ETIMEDOUT:
		return ReplyTTLExpired
	case syscall.ENETUNREACH:
		return ReplyNetworkUnreachable
	case syscall.EHOSTUNREACH:
		return ReplyHostUnreachable
	case syscall.ECONNREFUSED, syscall.ECONNRESET:
		return ReplyConnectionRefused
	default:
		return ReplyGeneralFailure
	}
}

// Request describes a SOCKS 5 request.
type Request struct {
	Auth AuthInfo
	Cmd  Command
	Addr Address

	conn net.Conn
}

type clientError ReplyCode

func (e clientError) Error() string {
	switch ReplyCode(e) {
	case ReplySucceeded:
		return "socks5: succeeded"
	case ReplyGeneralFailure:
		return "socks5: general failure"
	case ReplyConnectionNotAllowed:
		return "socks5: connection not allowed"
	case ReplyNetworkUnreachable:
		return "socks5: network unreachable"
	case ReplyHostUnreachable:
		return "socks5: host unreachable"
	case ReplyConnectionRefused:
		return "socks5: connection refused"
	case ReplyTTLExpired:
		return "socks5: ttl expired"
	case ReplyCommandNotSupported:
		return "socks5: command not supported"
	case ReplyAddressNotSupported:
		return "socks5: address not supported"
	default:
		return fmt.Sprintf("socks5: reply code: 0x%02x", e)
	}
}

func readByte(conn net.Conn) (byte, error) {
	var tmp [1]byte
	if _, err := conn.Read(tmp[:]); err != nil {
		return 0, err
	}
	return tmp[0], nil
}

func validateByte(descr string, val, expected byte) error {
	if val != expected {
		return fmt.Errorf("message field '%s' was 0x%02x (expected 0x%02x)", descr, val, expected)
	}
	return nil
}
