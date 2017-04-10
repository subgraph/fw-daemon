/*
 * server_rfc1929.go - SOCSK 5 server authentication.
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
)

const (
	authRFC1929Ver     = 0x01
	authRFC1929Success = 0x00
	authRFC1929Fail    = 0x01
)

// AuthInfo is the RFC 1929 Username/Password authentication data.
type AuthInfo struct {
	Uname  []byte
	Passwd []byte
}

func (req *Request) authRFC1929() (err error) {
	sendErrResp := func() {
		// Swallow write/flush errors, the auth failure is the relevant error.
		resp := []byte{authRFC1929Ver, authRFC1929Fail}
		req.conn.Write(resp[:])
	}

	// The client sends a Username/Password request.
	//  uint8_t ver (0x01)
	//  uint8_t ulen (>= 1)
	//  uint8_t uname[ulen]
	//  uint8_t plen (>= 1)
	//  uint8_t passwd[plen]

	if err = req.readByteVerify("auth version", authRFC1929Ver); err != nil {
		sendErrResp()
		return
	}

	// Read the username.
	var ulen byte
	if ulen, err = req.readByte(); err != nil {
		sendErrResp()
		return
	} else if ulen < 1 {
		sendErrResp()
		return fmt.Errorf("username with 0 length")
	}
	uname := make([]byte, ulen)
	if _, err = io.ReadFull(req.conn, uname); err != nil {
		sendErrResp()
		return
	}

	// Read the password.
	var plen byte
	if plen, err = req.readByte(); err != nil {
		sendErrResp()
		return
	} else if plen < 1 {
		sendErrResp()
		return fmt.Errorf("password with 0 length")
	}
	passwd := make([]byte, plen)
	if _, err = io.ReadFull(req.conn, passwd); err != nil {
		sendErrResp()
		return
	}

	req.Auth.Uname = uname
	req.Auth.Passwd = passwd

	resp := []byte{authRFC1929Ver, authRFC1929Success}
	_, err = req.conn.Write(resp[:])
	return
}
