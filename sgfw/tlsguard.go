package sgfw

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const TLSGUARD_READ_TIMEOUT = 2 * time.Second
const TLSGUARD_MIN_TLS_VER_MAJ = 3
const TLSGUARD_MIN_TLS_VER_MIN = 1

const SSL3_RT_CHANGE_CIPHER_SPEC = 20
const SSL3_RT_ALERT = 21
const SSL3_RT_HANDSHAKE = 22
const SSL3_RT_APPLICATION_DATA = 23

const SSL3_MT_SERVER_HELLO = 2
const SSL3_MT_CERTIFICATE = 11
const SSL3_MT_CERTIFICATE_REQUEST = 13
const SSL3_MT_SERVER_DONE = 14

func readTLSChunk(conn net.Conn) ([]byte, int, error) {
	conn.SetReadDeadline(time.Now().Add(TLSGUARD_READ_TIMEOUT))
	cbytes, err := readNBytes(conn, 5)
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		log.Errorf("TLS data chunk read failure: ", err)
		return nil, 0, err
	}

	if int(cbytes[1]) < TLSGUARD_MIN_TLS_VER_MAJ {
		return nil, 0, errors.New("TLS protocol major version less than expected minimum")
	} else if int(cbytes[2]) < TLSGUARD_MIN_TLS_VER_MIN {
		return nil, 0, errors.New("TLS protocol minor version less than expected minimum")
	}

	cbyte := cbytes[0]
	mlen := int(int(cbytes[3])<<8 | int(cbytes[4]))
	// fmt.Printf("TLS data chunk header read: type = %#x, maj = %v, min = %v, len = %v\n", cbyte, cbytes[1], cbytes[2], mlen)

	conn.SetReadDeadline(time.Now().Add(TLSGUARD_READ_TIMEOUT))
	cbytes2, err := readNBytes(conn, mlen)
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		return nil, 0, err
	}

	cbytes = append(cbytes, cbytes2...)
	return cbytes, int(cbyte), nil
}

func TLSGuard(conn, conn2 net.Conn, fqdn string) error {
	// Should this be a requirement?
	// if strings.HasSuffix(request.DestAddr.FQDN, "onion") {

	//conn client
	//conn2 server

	// Read the opening message from the client
	chunk, rtype, err := readTLSChunk(conn)
	if err != nil {
		return err
	}

	if rtype != SSL3_RT_HANDSHAKE {
		return errors.New("Blocked client from attempting non-TLS connection")
	}

	// Pass it on through to the server
	conn2.Write(chunk)

	// Read ServerHello
	valid := false
	loop := 1

	passthru := false

	for 1 == 1 {
		loop++

		// fmt.Printf("SSL LOOP %v; trying to read: conn2\n", loop)
		chunk, rtype, err = readTLSChunk(conn2)

		if err != nil {
			log.Debugf("TLSGUARD: OTHER loop %v: trying to read: conn\n", loop)
			chunk, rtype, err2 := readTLSChunk(conn)
			log.Debugf("TLSGUARD: read: %v, %v, %v\n", err2, rtype, len(chunk))

			if err2 == nil {
				conn2.Write(chunk)
				continue
			}

			return err
		}

		if rtype == SSL3_RT_CHANGE_CIPHER_SPEC || rtype == SSL3_RT_APPLICATION_DATA ||
			rtype == SSL3_RT_ALERT {
			// fmt.Println("OTHER DATA; PASSING THRU")
			passthru = true
		} else if rtype == SSL3_RT_HANDSHAKE {
			passthru = false
		} else {
			return errors.New(fmt.Sprintf("Expected TLS server handshake byte was not received [%#x vs 0x16]", rtype))
		}

		if passthru {
			// fmt.Println("passthru writing buf again and continuing:")
			conn.Write(chunk)
			continue
		}

		serverMsg := chunk[5:]
		s := serverMsg[0]
		log.Debugf("TLSGUARD: s = %#x\n", s)

		if s == SSL3_MT_CERTIFICATE {
			// Message len, 3 bytes
			serverMessageLen := serverMsg[1:4]
			serverMessageLenInt := int(int(serverMessageLen[0])<<16 | int(serverMessageLen[1])<<8 | int(serverMessageLen[2]))
			// fmt.Printf("chunk len = %v, serverMsgLen = %v, slint = %v\n", len(chunk), len(serverMsg), serverMessageLenInt)
			if len(serverMsg) < serverMessageLenInt {
				return errors.New(fmt.Sprintf("len(serverMsg) %v < serverMessageLenInt %v!\n", len(serverMsg), serverMessageLenInt))
			}
			serverHelloBody := serverMsg[4 : 4+serverMessageLenInt]
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

			// fmt.Println("ATTEMPTING TO VERIFY: ", fqdn)
			_, err = c.Verify(verifyOptions)
			// fmt.Println("ATTEMPTING TO VERIFY RESULT: ", err)
			if err != nil {
				return err
			} else {
				valid = true
			}
			// lse if s == 0x0d { fmt.Printf("found a client cert request, sending buf to client\n") }
		} else if s == SSL3_MT_SERVER_DONE {
			conn.Write(chunk)
			break
		} else if s == SSL3_MT_CERTIFICATE_REQUEST {
			break
		}
		// fmt.Printf("Sending chunk of type %d to client.\n", s)

		conn.Write(chunk)
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
