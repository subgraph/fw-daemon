package sgfw

import (
	"crypto/x509"
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

const SSL3_MT_SERVER_HELLO = 2
const SSL3_MT_CERTIFICATE = 11
const SSL3_MT_CERTIFICATE_REQUEST = 13
const SSL3_MT_SERVER_DONE = 14

type connReader struct {
	client bool
	data   []byte
	rtype  int
	err    error
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
					// fmt.Println("OTHER DATA; PASSING THRU")
					if cr.rtype == SSL3_RT_ALERT {
						fmt.Println("ALERT = ", cr.data)
					}
					other.Write(cr.data)
					continue
				} else if cr.client {
					other.Write(cr.data)
					continue
				} else if cr.rtype != SSL3_RT_HANDSHAKE {
					return errors.New(fmt.Sprintf("Expected TLS server handshake byte was not received [%#x vs 0x16]", cr.rtype))
				}

				serverMsg := cr.data[5:]
				s := serverMsg[0]
				fmt.Printf("s = %#x\n", s)

				if s > 0x22 {
					fmt.Println("WTF: ", cr.data)
				}

				if s == SSL3_MT_CERTIFICATE {
					fmt.Println("HMM")
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
