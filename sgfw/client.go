/*
 * client.go - SOCSK5 client implementation.
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

package sgfw

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Redispatch dials the provided proxy and redispatches an existing request.
func Redispatch(proxyNet, proxyAddr string, req *Request) (conn net.Conn, bndAddr *Address, err error) {
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()

	conn, err = clientHandshake(proxyNet, proxyAddr, req)
	if err != nil {
		return nil, nil, err
	}
	bndAddr, err = clientCmd(conn, req)
	return
}

func clientHandshake(proxyNet, proxyAddr string, req *Request) (net.Conn, error) {
	conn, err := net.Dial(proxyNet, proxyAddr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return conn, err
	}
	authMethod, err := clientNegotiateAuth(conn, req)
	if err != nil {
		return conn, err
	}
	if err := clientAuthenticate(conn, req, authMethod); err != nil {
		return conn, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return conn, err
	}

	return conn, nil
}

func clientNegotiateAuth(conn net.Conn, req *Request) (byte, error) {
	useRFC1929 := req.Auth.Uname != nil && req.Auth.Passwd != nil
	// XXX: Validate uname/passwd lengths, though should always be valid.

	var buf [3]byte
	buf[0] = version
	buf[1] = 1
	if useRFC1929 {
		buf[2] = authUsernamePassword
	} else {
		buf[2] = authNoneRequired
	}

	if _, err := conn.Write(buf[:]); err != nil {
		return authNoAcceptableMethods, err
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return authNoAcceptableMethods, err
	}
	if err := validateByte("version", resp[0], version); err != nil {
		return authNoAcceptableMethods, err
	}
	if err := validateByte("method", resp[1], buf[2]); err != nil {
		return authNoAcceptableMethods, err
	}

	return resp[1], nil
}

func clientAuthenticate(conn net.Conn, req *Request, authMethod byte) error {
	switch authMethod {
	case authNoneRequired:
	case authUsernamePassword:
		var buf []byte
		buf = append(buf, authRFC1929Ver)
		buf = append(buf, byte(len(req.Auth.Uname)))
		buf = append(buf, req.Auth.Uname...)
		buf = append(buf, byte(len(req.Auth.Passwd)))
		buf = append(buf, req.Auth.Passwd...)
		if _, err := conn.Write(buf); err != nil {
			return err
		}

		var resp [2]byte
		if _, err := io.ReadFull(conn, resp[:]); err != nil {
			return err
		}
		if err := validateByte("version", resp[0], authRFC1929Ver); err != nil {
			return err
		}
		if err := validateByte("status", resp[1], authRFC1929Success); err != nil {
			return err
		}
	default:
		panic(fmt.Sprintf("unknown authentication method: 0x%02x", authMethod))
	}
	return nil
}

func clientCmd(conn net.Conn, req *Request) (*Address, error) {
	var buf []byte
	buf = append(buf, version)
	buf = append(buf, byte(req.Cmd))
	buf = append(buf, rsv)
	buf = append(buf, req.Addr.raw...)
	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}

	var respHdr [3]byte
	if _, err := io.ReadFull(conn, respHdr[:]); err != nil {
		return nil, err
	}

	if err := validateByte("version", respHdr[0], version); err != nil {
		return nil, err
	}
	if err := validateByte("rep", respHdr[1], byte(ReplySucceeded)); err != nil {
		return nil, clientError(respHdr[1])
	}
	if err := validateByte("rsv", respHdr[2], rsv); err != nil {
		return nil, err
	}

	var bndAddr Address
	if err := bndAddr.read(conn); err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return &bndAddr, nil
}
