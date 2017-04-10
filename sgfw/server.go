/*
 * server.go - SOCSK5 server implementation.
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

package sgfw

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"
)

// Handshake attempts to handle a incoming client handshake over the provided
// connection and receive the SOCKS5 request.  The routine handles sending
// appropriate errors if applicable, but will not close the connection.
func Handshake(conn net.Conn) (*Request, error) {
	// Arm the handshake timeout.
	var err error
	if err = conn.SetDeadline(time.Now().Add(inboundTimeout)); err != nil {
		return nil, err
	}
	defer func() {
		// Disarm the handshake timeout, only propagate the error if
		// the handshake was successful.
		nerr := conn.SetDeadline(time.Time{})
		if err == nil {
			err = nerr
		}
	}()

	req := new(Request)
	req.conn = conn

	// Negotiate the protocol version and authentication method.
	var method byte
	if method, err = req.negotiateAuth(); err != nil {
		return nil, err
	}

	// Authenticate if neccecary.
	if err = req.authenticate(method); err != nil {
		return nil, err
	}

	// Read the client command.
	if err = req.readCommand(); err != nil {
		return nil, err
	}

	return req, err
}

// Reply sends a SOCKS5 reply to the corresponding request.  The BND.ADDR and
// BND.PORT fields are always set to an address/port corresponding to
// "0.0.0.0:0".
func (req *Request) Reply(code ReplyCode) error {
	return req.ReplyAddr(code, nil)
}

// ReplyAddr sends a SOCKS5 reply to the corresponding request.  The BND.ADDR
// and BND.PORT fields are specified by addr, or "0.0.0.0:0" if not provided.
func (req *Request) ReplyAddr(code ReplyCode, addr *Address) error {
	// The server sends a reply message.
	//  uint8_t ver (0x05)
	//  uint8_t rep
	//  uint8_t rsv (0x00)
	//  uint8_t atyp
	//  uint8_t bnd_addr[]
	//  uint16_t bnd_port

	resp := []byte{version, byte(code), rsv}
	if addr == nil {
		var nilAddr [net.IPv4len + 2]byte
		resp = append(resp, atypIPv4)
		resp = append(resp, nilAddr[:]...)
	} else {
		resp = append(resp, addr.raw...)
	}

	_, err := req.conn.Write(resp[:])
	return err

}

func (req *Request) negotiateAuth() (byte, error) {
	// The client sends a version identifier/selection message.
	//	uint8_t ver (0x05)
	//  uint8_t nmethods (>= 1).
	//  uint8_t methods[nmethods]

	var err error
	if err = req.readByteVerify("version", version); err != nil {
		return 0, err
	}

	// Read the number of methods, and the methods.
	var nmethods byte
	method := byte(authNoAcceptableMethods)
	if nmethods, err = req.readByte(); err != nil {
		return method, err
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(req.conn, methods); err != nil {
		return 0, err
	}

	// Pick the best authentication method, prioritizing authenticating
	// over not if both options are present.
	if bytes.IndexByte(methods, authUsernamePassword) != -1 {
		method = authUsernamePassword
	} else if bytes.IndexByte(methods, authNoneRequired) != -1 {
		method = authNoneRequired
	}

	// The server sends a method selection message.
	//  uint8_t ver (0x05)
	//  uint8_t method
	msg := []byte{version, method}
	if _, err = req.conn.Write(msg); err != nil {
		return 0, err
	}

	return method, nil
}

func (req *Request) authenticate(method byte) error {
	switch method {
	case authNoneRequired:
		return nil
	case authUsernamePassword:
		return req.authRFC1929()
	case authNoAcceptableMethods:
		return fmt.Errorf("no acceptable authentication methods")
	default:
		// This should never happen as only supported auth methods should be
		// negotiated.
		return fmt.Errorf("negotiated unsupported method 0x%02x", method)
	}
}

func (req *Request) readCommand() error {
	// The client sends the request details.
	//  uint8_t ver (0x05)
	//  uint8_t cmd
	//  uint8_t rsv (0x00)
	//  uint8_t atyp
	//  uint8_t dst_addr[]
	//  uint16_t dst_port

	var err error
	var cmd byte
	if err = req.readByteVerify("version", version); err != nil {
		req.Reply(ReplyGeneralFailure)
		return err
	}
	if cmd, err = req.readByte(); err != nil {
		req.Reply(ReplyGeneralFailure)
		return err
	}
	switch Command(cmd) {
	case CommandConnect, CommandTorResolve, CommandTorResolvePTR:
		req.Cmd = Command(cmd)
	default:
		req.Reply(ReplyCommandNotSupported)
		return fmt.Errorf("unsupported SOCKS command: 0x%02x", cmd)
	}
	if err = req.readByteVerify("reserved", rsv); err != nil {
		req.Reply(ReplyGeneralFailure)
		return err
	}

	// Read the destination address/port.
	err = req.Addr.read(req.conn)
	if err == errInvalidAtyp {
		req.Reply(ReplyAddressNotSupported)
	} else if err != nil {
		req.Reply(ReplyGeneralFailure)
	}

	return err
}

func (req *Request) readByte() (byte, error) {
	return readByte(req.conn)
}

func (req *Request) readByteVerify(descr string, expected byte) error {
	val, err := req.readByte()
	if err != nil {
		return err
	}
	return validateByte(descr, val, expected)
}
