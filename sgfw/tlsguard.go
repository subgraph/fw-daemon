package sgfw

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const TLSGUARD_READ_TIMEOUT = 5 * time.Second
const TLSGUARD_MIN_TLS_VER_MAJ = 3
const TLSGUARD_MIN_TLS_VER_MIN = 1

const SSL3_RT_CHANGE_CIPHER_SPEC = 20
const SSL3_RT_ALERT = 21
const SSL3_RT_HANDSHAKE = 22
const SSL3_RT_APPLICATION_DATA = 23

const SSL3_MT_HELLO_REQUEST = 0
const SSL3_MT_CLIENT_HELLO = 1
const SSL3_MT_SERVER_HELLO = 2
const SSL3_MT_CERTIFICATE = 11
const SSL3_MT_CERTIFICATE_REQUEST = 13
const SSL3_MT_SERVER_DONE = 14
const SSL3_MT_CERTIFICATE_STATUS = 22

const SSL3_AL_WARNING = 1
const SSL3_AL_FATAL = 2
const SSL3_AD_CLOSE_NOTIFY = 0
const SSL3_AD_UNEXPECTED_MESSAGE = 10
const SSL3_AD_BAD_RECORD_MAC = 20
const TLS1_AD_DECRYPTION_FAILED = 21
const TLS1_AD_RECORD_OVERFLOW = 22
const SSL3_AD_DECOMPRESSION_FAILURE = 30
const SSL3_AD_HANDSHAKE_FAILURE = 40
const SSL3_AD_NO_CERTIFICATE = 41
const SSL3_AD_BAD_CERTIFICATE = 42
const SSL3_AD_UNSUPPORTED_CERTIFICATE = 43
const SSL3_AD_CERTIFICATE_REVOKED = 44
const SSL3_AD_CERTIFICATE_EXPIRED = 45
const SSL3_AD_CERTIFICATE_UNKNOWN = 46
const SSL3_AD_ILLEGAL_PARAMETER = 47
const TLS1_AD_UNKNOWN_CA = 48
const TLS1_AD_ACCESS_DENIED = 49
const TLS1_AD_DECODE_ERROR = 50
const TLS1_AD_DECRYPT_ERROR = 51
const TLS1_AD_EXPORT_RESTRICTION = 60
const TLS1_AD_PROTOCOL_VERSION = 70
const TLS1_AD_INSUFFICIENT_SECURITY = 71
const TLS1_AD_INTERNAL_ERROR = 80
const TLS1_AD_INAPPROPRIATE_FALLBACK = 86
const TLS1_AD_USER_CANCELLED = 90
const TLS1_AD_NO_RENEGOTIATION = 100
const TLS1_AD_UNSUPPORTED_EXTENSION = 110

type connReader struct {
	client bool
	data   []byte
	rtype  int
	err    error
}

var cipherSuiteMap map[uint16]string = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
}

func getCipherSuiteName(value uint) string {
	val, ok := cipherSuiteMap[uint16(value)]
	if !ok {
		return "UNKNOWN"
	}

	return val
}

func connectionReader(conn net.Conn, is_client bool, c chan connReader, done chan bool) {
	var ret_error error = nil
	buffered := []byte{}
	mlen := 0
	rtype := 0
	stage := 1

	for {
		if ret_error != nil {
			cr := connReader{client: is_client, data: nil, rtype: 0, err: ret_error}
			c <- cr
			break
		}

		select {
		case <-done:
			fmt.Println("++ DONE: ", is_client)
			if len(buffered) > 0 {
				//fmt.Println("++ DONE BUT DISPOSING OF BUFFERED DATA")
				c <- connReader{client: is_client, data: buffered, rtype: 0, err: nil}
			}

			c <- connReader{client: is_client, data: nil, rtype: 0, err: nil}
			return
		default:
			if stage == 1 {
				header := make([]byte, 5)
				conn.SetReadDeadline(time.Now().Add(TLSGUARD_READ_TIMEOUT))
				_, err := io.ReadFull(conn, header)
				conn.SetReadDeadline(time.Time{})
				if err != nil {
					ret_error = err
					continue
				}

				if int(header[1]) < TLSGUARD_MIN_TLS_VER_MAJ {
					ret_error = errors.New("TLS protocol major version less than expected minimum")
					continue
				} else if int(header[2]) < TLSGUARD_MIN_TLS_VER_MIN {
					ret_error = errors.New("TLS protocol minor version less than expected minimum")
					continue
				}

				rtype = int(header[0])
				mlen = int(int(header[3])<<8 | int(header[4]))
				fmt.Printf("TLS data chunk header read: type = %#x, maj = %v, min = %v, len = %v\n", rtype, header[1], header[2], mlen)

				/*  16384+1024 if compression is not null */
				/*  or 16384+2048 if ciphertext */
				if mlen > 16384 {
					ret_error = errors.New(fmt.Sprintf("TLSGuard read TLS plaintext record of excessively large length; dropping (%v bytes)", mlen))
					continue
				}

				buffered = header
				stage++
			} else if stage == 2 {
				remainder := make([]byte, mlen)
				conn.SetReadDeadline(time.Now().Add(TLSGUARD_READ_TIMEOUT))
				_, err := io.ReadFull(conn, remainder)
				conn.SetReadDeadline(time.Time{})
				if err != nil {
					ret_error = err
					continue
				}

				buffered = append(buffered, remainder...)
				fmt.Printf("------- CHUNK READ: client: %v, err = %v, bytes = %v\n", is_client, err, len(buffered))
				cr := connReader{client: is_client, data: buffered, rtype: rtype, err: err}
				c <- cr

				buffered = []byte{}
				rtype = 0
				mlen = 0
				stage = 1
			}

		}

	}

}

func TLSGuard(conn, conn2 net.Conn, fqdn string) error {
	x509Valid := false
	ndone := 0
	// Should this be a requirement?
	// if strings.HasSuffix(request.DestAddr.FQDN, "onion") {

	//conn client
	//conn2 server

	fmt.Println("-------- STARTING HANDSHAKE LOOP")
	crChan := make(chan connReader)
	dChan := make(chan bool, 10)
	go connectionReader(conn, true, crChan, dChan)
	go connectionReader(conn2, false, crChan, dChan)

	client_expected := SSL3_MT_CLIENT_HELLO
	server_expected := SSL3_MT_SERVER_HELLO

select_loop:
	for {
		if ndone == 2 {
			fmt.Println("DONE channel got both notifications. Terminating loop.")
			close(dChan)
			close(crChan)
			break
		}

		select {
		case cr := <-crChan:
			other := conn

			if cr.client {
				other = conn2
			}

			fmt.Printf("++++ SELECT: %v, %v, %v\n", cr.client, cr.err, len(cr.data))
			if cr.err == nil && cr.data == nil {
				fmt.Println("DONE channel notification received")
				ndone++
				continue
			}

			if cr.err == nil {
				if cr.rtype == SSL3_RT_CHANGE_CIPHER_SPEC || cr.rtype == SSL3_RT_APPLICATION_DATA ||
					cr.rtype == SSL3_RT_ALERT {

					/* We expect only a single byte of data */
					if cr.rtype == SSL3_RT_CHANGE_CIPHER_SPEC {
						if len(cr.data) != 6 {
							return errors.New(fmt.Sprintf("TLSGuard dropped connection with strange change cipher spec data length (%v bytes)", len(cr.data)))
						}
						if cr.data[5] != 1 {
							return errors.New(fmt.Sprintf("TLSGuard dropped connection with strange change cipher spec data (%#x bytes)", cr.data[5]))
						}
					} else if cr.rtype == SSL3_RT_ALERT {
						if cr.data[5] == SSL3_AL_WARNING {
							fmt.Println("SSL ALERT TYPE: warning")
						} else if cr.data[5] == SSL3_AL_FATAL {
							fmt.Println("SSL ALERT TYPE: fatal")
						} else {
							fmt.Println("SSL ALERT TYPE UNKNOWN")
						}

						alert_desc := int(int(cr.data[6])<<8 | int(cr.data[7]))
						fmt.Println("ALERT DESCRIPTION: ", alert_desc)

						if cr.data[5] == SSL3_AL_FATAL {
							return errors.New(fmt.Sprintf("TLSGuard dropped connection after fatal error alert detected"))
						} else if alert_desc == SSL3_AD_CLOSE_NOTIFY {
							return errors.New(fmt.Sprintf("TLSGuard dropped connection after close_notify alert detected"))
						}

					}

					// fmt.Println("OTHER DATA; PASSING THRU")
					if cr.rtype == SSL3_RT_ALERT {
						fmt.Println("ALERT = ", cr.data)
					}
					other.Write(cr.data)
					continue
				} else if cr.client {
					//					other.Write(cr.data)
					//					continue
				} else if cr.rtype != SSL3_RT_HANDSHAKE {
					return errors.New(fmt.Sprintf("Expected TLS server handshake byte was not received [%#x vs 0x16]", cr.rtype))
				}

				if cr.rtype < SSL3_RT_CHANGE_CIPHER_SPEC || cr.rtype > SSL3_RT_APPLICATION_DATA {
					return errors.New(fmt.Sprintf("TLSGuard dropping connection with unknown content type: %#x", cr.rtype))
				}

				handshakeMsg := cr.data[5:]
				s := uint(handshakeMsg[0])
				fmt.Printf("s = %#x\n", s)

				if cr.client && s != uint(client_expected) {
					return errors.New(fmt.Sprintf("Client sent handshake type %#x but expected %#x", s, client_expected))
				} else if !cr.client && s != uint(server_expected) {
					return errors.New(fmt.Sprintf("Server sent handshake type %#x but expected %#x", s, server_expected))
				}

				if cr.client {
					if s == SSL3_MT_CLIENT_HELLO {
						fmt.Println("CLIENT HELLO")
						hello_offset := 4
						// 2 byte protocol version
						fmt.Println("CLIENT HELLO VERSION = ", handshakeMsg[hello_offset:hello_offset+2])
						hello_offset += 2
						// 4 byte Random/GMT time
						fmt.Println("CLIENT HELLO GMT = ", handshakeMsg[hello_offset:hello_offset+4])
						hello_offset += 4
						// 28 bytes Random/random_bytes
						hello_offset += 28
						// 1 byte (32-bit session ID)
						fmt.Println("CLIENT HELLO SESSION ID = ", handshakeMsg[hello_offset:hello_offset+1])
						hello_offset++
						// 2 byte cipher suite array
						cs := binary.BigEndian.Uint16(handshakeMsg[hello_offset : hello_offset+2])
						fmt.Printf("cs = %v / %#v\n", cs, cs)
						fmt.Printf("CLIENT HELLO CIPHERSUITE: %v (%s)\n", handshakeMsg[hello_offset:hello_offset+2], getCipherSuiteName(uint(cs)))
					}

					other.Write(cr.data)
					continue
				}

				if !cr.client && s == SSL3_MT_HELLO_REQUEST {
					fmt.Println("Server sent hello request")
					continue
				}

				if s > SSL3_MT_CERTIFICATE_STATUS {
					fmt.Println("WTF: ", cr.data)
				}

				// Message len, 3 bytes
				handshakeMessageLen := handshakeMsg[1:4]
				handshakeMessageLenInt := int(int(handshakeMessageLen[0])<<16 | int(handshakeMessageLen[1])<<8 | int(handshakeMessageLen[2]))

				if s == SSL3_MT_CERTIFICATE {
					fmt.Println("HMM")
					// fmt.Printf("chunk len = %v, handshakeMsgLen = %v, slint = %v\n", len(chunk), len(handshakeMsg), handshakeMessageLenInt)
					if len(handshakeMsg) < handshakeMessageLenInt {
						return errors.New(fmt.Sprintf("len(handshakeMsg) %v < handshakeMessageLenInt %v!\n", len(handshakeMsg), handshakeMessageLenInt))
					}
					serverHelloBody := handshakeMsg[4 : 4+handshakeMessageLenInt]
					certChainLen := int(int(serverHelloBody[0])<<16 | int(serverHelloBody[1])<<8 | int(serverHelloBody[2]))
					remaining := certChainLen
					pos := serverHelloBody[3:certChainLen]

					// var certChain []*x509.Certificate
					var verifyOptions x509.VerifyOptions

					//fqdn = "www.reddit.com"
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
					fmt.Println("ATTEMPTING TO VERIFY: ", fqdn)
					_, err := c.Verify(verifyOptions)
					fmt.Println("ATTEMPTING TO VERIFY RESULT: ", err)
					if err != nil {
						return err
					} else {
						x509Valid = true
					}
				}

				other.Write(cr.data)

				if x509Valid || (s == SSL3_MT_SERVER_DONE) || (s == SSL3_MT_CERTIFICATE_REQUEST) {
					fmt.Println("BREAKING OUT OF LOOP 1")
					dChan <- true
					fmt.Println("BREAKING OUT OF LOOP 2")
					break select_loop
				}

				// fmt.Printf("Sending chunk of type %d to client.\n", s)
			} else if cr.err != nil {
				ndone++

				if cr.client {
					fmt.Println("Client read error: ", cr.err)
				} else {
					fmt.Println("Server read error: ", cr.err)
				}

				return cr.err
			}

		}
	}

	fmt.Println("WAITING; ndone = ", ndone)
	for ndone < 2 {
		fmt.Println("WAITING; ndone = ", ndone)
		select {
		case cr := <-crChan:
			fmt.Printf("CHAN DATA: %v, %v, %v\n", cr.client, cr.err, len(cr.data))
			if cr.err != nil || cr.data == nil {
				ndone++
			} else if cr.client {
				conn2.Write(cr.data)
			} else if !cr.client {
				conn.Write(cr.data)
			}

		}
	}

	fmt.Println("______ ndone = 2\n")

	//	dChan <- true
	close(dChan)

	if !x509Valid {
		return errors.New("Unknown error: TLS connection could not be validated")
	}

	return nil

}
