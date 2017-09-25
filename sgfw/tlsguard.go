package sgfw

import (
	"crypto/x509"
	"errors"
	"io"
	"net"
)

func TLSGuard(conn, conn2 net.Conn, fqdn string) error {
	// Should this be a requirement?
	//	if strings.HasSuffix(request.DestAddr.FQDN, "onion") {

	handshakeByte, err := readNBytes(conn, 1)
	if err != nil {
		return err
	}

	if handshakeByte[0] != 0x16 {
		return errors.New("Blocked client from attempting non-TLS connection")
	}

	vers, err := readNBytes(conn, 2)
	if err != nil {
		return err
	}

	length, err := readNBytes(conn, 2)
	if err != nil {
		return err
	}

	ffslen := int(int(length[0])<<8 | int(length[1]))

	ffs, err := readNBytes(conn, ffslen)
	if err != nil {
		return err
	}

	// Transmit client hello
	conn2.Write(handshakeByte)
	conn2.Write(vers)
	conn2.Write(length)
	conn2.Write(ffs)

	// Read ServerHello
	bytesRead := 0
	var s byte // 0x0e is done
	var responseBuf []byte = []byte{}
	valid := false
	sendToClient := false

	for sendToClient == false {
		// Handshake byte
		serverhandshakeByte, err := readNBytes(conn2, 1)
		if err != nil {
			return nil
		}

		responseBuf = append(responseBuf, serverhandshakeByte[0])
		bytesRead += 1

		if serverhandshakeByte[0] != 0x16 {
			return errors.New("Expected TLS server handshake byte was not received")
		}

		// Protocol version, 2 bytes
		serverProtocolVer, err := readNBytes(conn2, 2)
		if err != nil {
			return err
		}

		bytesRead += 2
		responseBuf = append(responseBuf, serverProtocolVer...)

		// Record length, 2 bytes
		serverRecordLen, err := readNBytes(conn2, 2)
		if err != nil {
			return err
		}

		bytesRead += 2
		responseBuf = append(responseBuf, serverRecordLen...)
		serverRecordLenInt := int(int(serverRecordLen[0])<<8 | int(serverRecordLen[1]))

		// Record type byte
		serverMsg, err := readNBytes(conn2, serverRecordLenInt)
		if err != nil {
			return err
		}

		bytesRead += len(serverMsg)
		responseBuf = append(responseBuf, serverMsg...)
		s = serverMsg[0]

		// Message len, 3 bytes
		serverMessageLen := serverMsg[1:4]
		serverMessageLenInt := int(int(serverMessageLen[0])<<16 | int(serverMessageLen[1])<<8 | int(serverMessageLen[2]))

		// serverHelloBody, err := readNBytes(conn2, serverMessageLenInt)
		serverHelloBody := serverMsg[4 : 4+serverMessageLenInt]

		if s == 0x0b {
			certChainLen := int(int(serverHelloBody[0])<<16 | int(serverHelloBody[1])<<8 | int(serverHelloBody[2]))
			remaining := certChainLen
			pos := serverHelloBody[3:certChainLen]

			// var certChain []*x509.Certificate
			var verifyOptions x509.VerifyOptions

			if fqdn != "" {
				verifyOptions.DNSName = fqdn
			}

			pool := x509.NewCertPool()
			var c *x509.Certificate

			for remaining > 0 {
				certLen := int(int(pos[0])<<16 | int(pos[1])<<8 | int(pos[2]))
				// fmt.Printf("Certs chain len %d, cert 1 len %d:\n", certChainLen, certLen)
				cert := pos[3 : 3+certLen]
				certs, err := x509.ParseCertificates(cert)
				if remaining == certChainLen {
					c = certs[0]
				} else {
					pool.AddCert(certs[0])
				}
				// certChain = append(certChain, certs[0])
				if err != nil {
					return err
				}
				remaining = remaining - certLen - 3
				if remaining > 0 {
					pos = pos[3+certLen:]
				}
			}
			verifyOptions.Intermediates = pool

			_, err = c.Verify(verifyOptions)
			if err != nil {
				return err
			} else {
				valid = true
			}
			//		else if s == 0x0d {		fmt.Printf("found a client cert request, sending buf to client\n") }
		} else if s == 0x0e {
			sendToClient = true
		} else if s == 0x0d {
			sendToClient = true
		}

		// fmt.Printf("Version bytes: %x %x\n", responseBuf[1], responseBuf[2])
		// fmt.Printf("Len bytes: %x %x\n", responseBuf[3], responseBuf[4])
		// fmt.Printf("Message type: %x\n", responseBuf[5])
		// fmt.Printf("Message len: %x %x %x\n", responseBuf[6], responseBuf[7], responseBuf[8])
		// fmt.Printf("Message body: %v\n", responseBuf[9:])
		conn.Write(responseBuf)
		responseBuf = []byte{}
	}

	if !valid {
		return errors.New("Unknown error: TLS connection could not be validated")
	}

	return nil
}

func readNBytes(conn net.Conn, numBytes int) ([]byte, error) {
	res := make([]byte, 0)
	temp := make([]byte, 1)
	for i := 0; i < numBytes; i++ {
		_, err := io.ReadAtLeast(conn, temp, 1)
		if err != nil {
			return res, err
		}
		res = append(res, temp[0])
	}
	return res, nil
}
