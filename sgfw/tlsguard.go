package sgfw

import (
	"crypto/x509"
	"encoding/binary"
	//	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"math/rand"
)

const TLSGUARD_READ_TIMEOUT = 8 * time.Second
const TLSGUARD_MIN_TLS_VER_MAJ = 3
const TLSGUARD_MIN_TLS_VER_MIN = 1

const TLS_RECORD_HDR_LEN = 5

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

const TLSEXT_TYPE_server_name = 0
const TLSEXT_TYPE_max_fragment_length = 1
const TLSEXT_TYPE_client_certificate_url = 2
const TLSEXT_TYPE_trusted_ca_keys = 3
const TLSEXT_TYPE_truncated_hmac = 4
const TLSEXT_TYPE_status_request = 5
const TLSEXT_TYPE_user_mapping = 6
const TLSEXT_TYPE_client_authz = 7
const TLSEXT_TYPE_server_authz = 8
const TLSEXT_TYPE_cert_type = 9
const TLSEXT_TYPE_supported_groups = 10
const TLSEXT_TYPE_ec_point_formats = 11
const TLSEXT_TYPE_srp = 12
const TLSEXT_TYPE_signature_algorithms = 13
const TLSEXT_TYPE_use_srtp = 14
const TLSEXT_TYPE_heartbeat = 15
const TLSEXT_TYPE_application_layer_protocol_negotiation = 16
const TLSEXT_TYPE_status_request_v2 = 17
const TLSEXT_TYPE_signed_certificate_timestamp = 18
const TLSEXT_TYPE_client_certificate_type = 19
const TLSEXT_TYPE_server_certificate_type = 20
const TLSEXT_TYPE_padding = 21
const TLSEXT_TYPE_encrypt_then_mac = 22
const TLSEXT_TYPE_extended_master_secret = 23
const TLSEXT_TYPE_token_binding = 24
const TLSEXT_TYPE_cached_info = 25
const TLSEXT_TYPE_SessionTicket = 35
const TLSEXT_TYPE_renegotiate = 0xff01

var tlsExtensionMap map[uint16]string = map[uint16]string{
	TLSEXT_TYPE_server_name:                            "TLSEXT_TYPE_server_name",
	TLSEXT_TYPE_max_fragment_length:                    "TLSEXT_TYPE_max_fragment_length",
	TLSEXT_TYPE_client_certificate_url:                 "TLSEXT_TYPE_client_certificate_url",
	TLSEXT_TYPE_trusted_ca_keys:                        "TLSEXT_TYPE_trusted_ca_keys",
	TLSEXT_TYPE_truncated_hmac:                         "TLSEXT_TYPE_truncated_hmac",
	TLSEXT_TYPE_status_request:                         "TLSEXT_TYPE_status_request",
	TLSEXT_TYPE_user_mapping:                           "TLSEXT_TYPE_user_mapping",
	TLSEXT_TYPE_client_authz:                           "TLSEXT_TYPE_client_authz",
	TLSEXT_TYPE_server_authz:                           "TLSEXT_TYPE_server_authz",
	TLSEXT_TYPE_cert_type:                              "TLSEXT_TYPE_cert_type",
	TLSEXT_TYPE_supported_groups:                       "TLSEXT_TYPE_supported_groups",
	TLSEXT_TYPE_ec_point_formats:                       "TLSEXT_TYPE_ec_point_formats",
	TLSEXT_TYPE_srp:                                    "TLSEXT_TYPE_srp",
	TLSEXT_TYPE_signature_algorithms:                   "TLSEXT_TYPE_signature_algorithms",
	TLSEXT_TYPE_use_srtp:                               "TLSEXT_TYPE_use_srtp",
	TLSEXT_TYPE_heartbeat:                              "TLSEXT_TYPE_heartbeat",
	TLSEXT_TYPE_application_layer_protocol_negotiation: "TLSEXT_TYPE_application_layer_protocol_negotiation",
	TLSEXT_TYPE_status_request_v2:                      "TLSEXT_TYPE_status_request_v2",
	TLSEXT_TYPE_signed_certificate_timestamp:           "TLSEXT_TYPE_signed_certificate_timestamp",
	TLSEXT_TYPE_client_certificate_type:                "TLSEXT_TYPE_client_certificate_type",
	TLSEXT_TYPE_server_certificate_type:                "TLSEXT_TYPE_server_certificate_type",
	TLSEXT_TYPE_padding:                                "TLSEXT_TYPE_padding",
	TLSEXT_TYPE_encrypt_then_mac:                       "TLSEXT_TYPE_encrypt_then_mac",
	TLSEXT_TYPE_extended_master_secret:                 "TLSEXT_TYPE_extended_master_secret",
	TLSEXT_TYPE_token_binding:                          "TLSEXT_TYPE_token_binding",
	TLSEXT_TYPE_cached_info:                            "TLSEXT_TYPE_cached_info",
	TLSEXT_TYPE_SessionTicket:                          "TLSEXT_TYPE_SessionTicket",
	TLSEXT_TYPE_renegotiate:                            "TLSEXT_TYPE_renegotiate",
}

type connReader struct {
	client bool
	data   []byte
	rtype  int
	err    error
	numb    int
}

var cipherSuiteMap map[uint16]string = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00c4: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
	0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xc076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
	0xc077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
	0xcc13: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcc14: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcc15: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

var whitelistedCiphers = []string{
	"SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	"TLS_RSA_WITH_AES_128_CBC_SHA",
	"SSL_RSA_WITH_3DES_EDE_CBC_SHA",
}

var blacklistedCiphers = []string{
	"TLS_NULL_WITH_NULL_NULL",
	"TLS_RSA_WITH_AES_128_CBC_SHA",
}

func getCipherSuiteName(value uint) string {
	val, ok := cipherSuiteMap[uint16(value)]
	if !ok {
		return "UNKNOWN"
	}

	return val
}

func isBadCipher(cname string) bool {
	for _, cipher := range blacklistedCiphers {
		if cipher == cname {
			return true
		}
	}

	return false
}

func gettlsExtensionName(value uint) string {
	// 26-34: Unassigned
	// 36-65280: Unassigned
	// 65282-65535: Unassigned

	if (value >= 26 && value <= 34) || (value >= 36 && value <= 65280) || (value >= 65282 && value <= 65535) {
		return fmt.Sprintf("Unassigned TLS Extension %#x", value)
	}

	val, ok := tlsExtensionMap[uint16(value)]
	if !ok {
		return "UNKNOWN"
	}

	return val
}

func stripTLSData(record []byte, start_ind, end_ind int, len_ind int, len_size int) []byte {
	var size uint = 0

	if len_size < 1 || len_size > 2 {
		return nil
	} else if start_ind >= end_ind {
		return nil
	} else if len_ind >= start_ind {
		return nil
	}

	rcopy := make([]byte, len(record))
	copy(rcopy, record)

	if len_size == 1 {
		size = uint(rcopy[len_ind])
	} else if len_size == 2 {
		size = uint(binary.BigEndian.Uint16(rcopy[len_ind : len_ind+len_size]))
	}

	size -= uint(end_ind - start_ind)

	// Put back the length size
	if len_size == 1 {
		rcopy[len_ind] = byte(size)
	} else if len_size == 2 {
		binary.BigEndian.PutUint16(rcopy[len_ind:len_ind+len_size], uint16(size))
	}

	// Patch the record size
	rsize := binary.BigEndian.Uint16(rcopy[3:5])
	rsize -= uint16(end_ind - start_ind)
	binary.BigEndian.PutUint16(rcopy[3:5], rsize)

	// And finally the 3 byte hello record
	hsize := binary.BigEndian.Uint32(rcopy[5:9])
	saved_b := hsize & 0xff000000
	hsize &= 0x00ffffff
	hsize -= uint32(end_ind - start_ind)
	hsize |= saved_b
	binary.BigEndian.PutUint32(rcopy[5:9], hsize)

	result := append(rcopy[:start_ind], rcopy[end_ind:]...)
	return result
}

func connectionReader(conn net.Conn, is_client bool, c chan connReader, done chan bool, num int) {
	var ret_error error = nil
	buffered := []byte{}
	mlen := 0
	rtype := 0
	stage := 1
	proceed := true

	for {
		if ret_error != nil {
			cr := connReader{client: is_client, data: nil, rtype: 0, err: ret_error, numb: num}
			c <- cr
			break
		}
		//fmt.Printf("why i am here %v %d\n", is_client, num)
		//if is_client == true && proceed == false {
		if proceed == false {
			if len(buffered) > 0 {
				c <- connReader{client: is_client, data: buffered, rtype:0, err: nil, numb: num}
			}
			c <- connReader{client: is_client, data: nil, rtype: 0, err: nil}
			return
		}
		select {
		case <-done:
		//	fmt.Printf("++ DONE %d: %v\n", num, is_client)
			if len(buffered) > 0 {
		//		fmt.Printf("++ DONE BUT DISPOSING OF BUFFERED DATA num: %d\n", num)
				c <- connReader{client: is_client, data: buffered, rtype: 0, err: nil, numb: num}
			}
			c <- connReader{client: is_client, data: nil, rtype: 0, err: nil, numb: num}
			return
		default:
			if stage == 1 && proceed == true {
				header := make([]byte, TLS_RECORD_HDR_LEN)
				conn.SetReadDeadline(time.Now().Add(TLSGUARD_READ_TIMEOUT))
		//		fmt.Printf("About to read here stage 1 %v %d\n", is_client, num)
				_, err := io.ReadFull(conn, header)
				// fmt.Printf("Read here stage 1 %v num %d \n", is_client, num)
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
				} else if int(header[1]) > 3 {
					ret_error = errors.New("TLS protocol major version was larger than expected; maybe not TLS handshake?")
					continue
				}

				rtype = int(header[0])
				mlen = int(int(header[3])<<8 | int(header[4]))
				//fmt.Printf("TLS data chunk header read: type = %#x, maj = %v, min = %v, len = %v\n", rtype, header[1], header[2], mlen)

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
				// fmt.Printf("About to read here stage 2 %v num %d\n", is_client, num)
				conn.SetReadDeadline(time.Now().Add(TLSGUARD_READ_TIMEOUT))
				_, err := io.ReadFull(conn, remainder)
				conn.SetReadDeadline(time.Time{})
				if err != nil {
					ret_error = err
					continue
				}

				buffered = append(buffered, remainder...)
				// fmt.Printf("------- CHUNK READ: client: %v, err = %v, bytes = %v\n", is_client, err, len(buffered))
				cr := connReader{client: is_client, data: buffered, rtype: rtype, err: err, numb: num}
				c <- cr

				buffered = []byte{}
				rtype = 0
				mlen = 0
				stage = 1
				//proceed = false
				if is_client {
					proceed = false
				}
			}

		}

	}

}

func isExpected(val uint, possibilities []uint) bool {
	for _, pval := range possibilities {
		if val == pval {
			return true
		}
	}

	return false
}

func TLSGuard(conn, conn2 net.Conn, fqdn string) error {
	x509Valid := false
	ndone := 0
	// Should this be a requirement?
	// if strings.HasSuffix(request.DestAddr.FQDN, "onion") {

	//conn client
	//conn2 server

	// fmt.Println("-------- STARTING HANDSHAKE LOOP")
	crChan := make(chan connReader)
	dChan := make(chan bool, 10)
	dChan2 := make(chan bool, 10)
	rand.Seed(time.Now().UTC().UnixNano())
	connectThread1 := rand.Intn(1000)
	connectThread2 := rand.Intn(1000)
	go connectionReader(conn, true, crChan, dChan, connectThread1)
	go connectionReader(conn2, false, crChan, dChan2, connectThread2)

	client_expected := []uint{SSL3_MT_CLIENT_HELLO}
	server_expected := []uint{SSL3_MT_SERVER_HELLO}

	client_sess := false
	server_sess := false
	client_change_cipher := false
	server_change_cipher := false

select_loop:
	for {
		if ndone == 2 {
			// fmt.Println("DONE channel got both notifications. Terminating loop.")
			close(dChan)
			close(dChan2)
			close(crChan)
			break
		}

		select {
		case cr := <-crChan:
			other := conn

			if cr.client {
				other = conn2
			}

			//fmt.Printf("++++ SELECT: %v, %v, %v\n", cr.client, cr.err, len(cr.data))
			if cr.err == nil && cr.data == nil {
			//	fmt.Println("DONE channel notification received")
				ndone++
				continue
			}

			if cr.err == nil {
				if cr.rtype == SSL3_RT_CHANGE_CIPHER_SPEC || cr.rtype == SSL3_RT_APPLICATION_DATA ||
					cr.rtype == SSL3_RT_ALERT {

					/* We expect only a single byte of data */
					if cr.rtype == SSL3_RT_CHANGE_CIPHER_SPEC {
			//			fmt.Println("CHANGE CIPHER_SPEC: ", cr.data[TLS_RECORD_HDR_LEN])
						if len(cr.data) != 6 {
							return errors.New(fmt.Sprintf("TLSGuard dropped connection with strange change cipher spec data length (%v bytes)", len(cr.data)))
						}
						if cr.data[TLS_RECORD_HDR_LEN] != 1 {
							return errors.New(fmt.Sprintf("TLSGuard dropped connection with strange change cipher spec data (%#x bytes)", cr.data[TLS_RECORD_HDR_LEN]))
						}

						if cr.client {
							client_change_cipher = true
						} else {
							server_change_cipher = true
							x509Valid = true
							dChan <- true
							dChan2 <- true		
						}
					} else if cr.rtype == SSL3_RT_ALERT {
						if cr.data[TLS_RECORD_HDR_LEN] == SSL3_AL_WARNING {
							fmt.Println("SSL ALERT TYPE: warning")
						} else if cr.data[TLS_RECORD_HDR_LEN] == SSL3_AL_FATAL {
							fmt.Println("SSL ALERT TYPE: fatal")
						} else {
							fmt.Println("SSL ALERT TYPE UNKNOWN")
						}

						alert_desc := int(int(cr.data[5])<<8 | int(cr.data[6]))
						fmt.Println("ALERT DESCRIPTION: ", alert_desc)

						if cr.data[TLS_RECORD_HDR_LEN] == SSL3_AL_FATAL {
							return errors.New(fmt.Sprintf("TLSGuard dropped connection after fatal error alert detected"))
						} else if alert_desc == SSL3_AD_CLOSE_NOTIFY {
							return errors.New(fmt.Sprintf("TLSGuard dropped connection after close_notify alert detected"))
						}

					}
					other.Write(cr.data)
					continue
				} else if cr.rtype != SSL3_RT_HANDSHAKE {
					return errors.New(fmt.Sprintf("Expected TLS server handshake byte was not received [%#x vs 0x16]", cr.rtype))
				}

				handshakeMsg := cr.data[TLS_RECORD_HDR_LEN:]
				s := uint(handshakeMsg[0])
				handshakeMessageLen := handshakeMsg[1:4]
				handshakeMessageLenInt := int(int(handshakeMessageLen[0])<<16 | int(handshakeMessageLen[1])<<8 | int(handshakeMessageLen[2]))
				// fmt.Printf("s = %#x, lenint = %v, total = %d\n", s, handshakeMessageLenInt, len(cr.data))

				if (client_sess || server_sess) && (client_change_cipher || server_change_cipher) {

					 if handshakeMessageLenInt > len(cr.data)+9 {
						log.Notice("TLSGuard saw what looks like a resumed encrypted session... passing connection through")
						x509Valid = true
						other.Write(cr.data)
						dChan2 <- true
						dChan <- true
						break select_loop
					}

				}

				if cr.client && !isExpected(s, client_expected) {
					return errors.New(fmt.Sprintf("Client sent handshake type %#x but expected %#x", s, client_expected))
				} else if !cr.client && !isExpected(s, server_expected) {
					return errors.New(fmt.Sprintf("Server sent handshake type %#x but expected %#x", s, server_expected))
				}

				if (cr.client && s == SSL3_MT_CLIENT_HELLO) || (!cr.client && s == SSL3_MT_SERVER_HELLO) {
					//					rewrite := false
					//					rewrite_buf := []byte{}
					//SRC := ""
					if s != SSL3_MT_CLIENT_HELLO {
						//SRC = "CLIENT"
					//} else {
						server_expected = []uint{SSL3_MT_CERTIFICATE, SSL3_MT_HELLO_REQUEST}
					//	SRC = "SERVER"
					}
					hello_offset := 4
					// 2 byte protocol version
					// fmt.Println(SRC, "HELLO VERSION = ", handshakeMsg[hello_offset:hello_offset+2])
					hello_offset += 2
					// 4 byte Random/GMT time
					//gmtbytes := binary.BigEndian.Uint32(handshakeMsg[hello_offset : hello_offset+4])
					//gmt := time.Unix(int64(gmtbytes), 0)
					//fmt.Println(SRC, "HELLO GMT = ", gmt)
					hello_offset += 4
					// 28 bytes Random/random_bytes
					hello_offset += 28
					// 1 byte (32-bit session ID)
					sess_len := uint(handshakeMsg[hello_offset])
					// fmt.Println(SRC, "HELLO SESSION ID = ", sess_len)

					if cr.client && sess_len > 0 {
						client_sess = true
					} else {
						server_sess = true
					}

					/*				
										hello_offset += int(sess_len) + 1
										// 2 byte cipher suite array
										cs := binary.BigEndian.Uint16(handshakeMsg[hello_offset : hello_offset+2])
										noCS := cs
										fmt.Printf("cs = %v / %#x\n", noCS, noCS)

										saved_ciphersuite_size_off := hello_offset

										if !cr.client {
											fmt.Printf("SERVER selected ciphersuite: %#x (%s)\n", cs, getCipherSuiteName(uint(cs)))
											hello_offset += 2
										} else {

											for csind := 0; csind < int(noCS/2); csind++ {
												off := hello_offset + 2 + (csind * 2)
												cs = binary.BigEndian.Uint16(handshakeMsg[off : off+2])
												cname := getCipherSuiteName(uint(cs))
												fmt.Printf("%s HELLO CIPHERSUITE: %d/%d: %#x (%s)\n", SRC, csind+1, noCS/2, cs, cname)

												if isBadCipher(cname) {
													fmt.Println("BAD CIPHER: ", cname)
												}

											}

											hello_offset += 2 + int(noCS)
										}

										clen := uint(handshakeMsg[hello_offset])
										hello_offset++

										if !cr.client {
											fmt.Println("SERVER selected compression method: ", clen)
										} else {
											fmt.Println(SRC, "HELLO COMPRESSION METHODS LEN = ", clen)
											fmt.Println(SRC, "HELLO COMPRESSION METHODS: ", handshakeMsg[hello_offset:hello_offset+int(clen)])
											hello_offset += int(clen)
										}

										var extlen uint16 = 0

										if hello_offset == len(handshakeMsg) {
											fmt.Println("Message didn't have any extensions present")
										} else {
											extlen = binary.BigEndian.Uint16(handshakeMsg[hello_offset : hello_offset+2])
											fmt.Println(SRC, "HELLO EXTENSIONS LENGTH: ", extlen)
											hello_offset += 2
										}

										if cr.client {
											ext_ctr := 0

											for ext_ctr < int(extlen)-2 {
												exttype := binary.BigEndian.Uint16(handshakeMsg[hello_offset : hello_offset+2])
												hello_offset += 2
												ext_ctr += 2
												//							fmt.Printf("PROGRESS: %v of %v, %v of %v\n", ext_ctr, extlen, hello_offset, len(handshakeMsg))
												fmt.Printf("EXTTYPE = %#x (%s)\n", exttype, gettlsExtensionName(uint(exttype)))
												inner_len := binary.BigEndian.Uint16(handshakeMsg[hello_offset : hello_offset+2])
												hello_offset += int(inner_len) + 2
												ext_ctr += int(inner_len) + 2
											}

										}*/

					other.Write(cr.data)
					continue
				}

				if cr.client {
					other.Write(cr.data)
					continue
				}

				if !cr.client && isExpected(SSL3_MT_SERVER_HELLO, server_expected) {
					server_expected = []uint{SSL3_MT_CERTIFICATE}
				}
				if !cr.client && s == SSL3_MT_HELLO_REQUEST {
					// fmt.Println("Server sent hello request")
/*					if server_change_cipher {
						x509Valid = true
						other.Write(cr.data)
						dChan <- true
						dChan2 <- true
						break select_loop
					}
*/
					other.Write(cr.data)
					continue
				}

				if s > SSL3_MT_CERTIFICATE_STATUS {
					fmt.Println("WTF: ", cr.data)
				}

				if s == SSL3_MT_CERTIFICATE {
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
					// fmt.Println("ATTEMPTING TO VERIFY: ", fqdn)
					_, err := c.Verify(verifyOptions)
					// fmt.Println("ATTEMPTING TO VERIFY RESULT: ", err)
					if err != nil {
						return err
					} else {
						x509Valid = true
						other.Write(cr.data)
						dChan <- true
						dChan2 <- true
						break select_loop
					}
				}

				other.Write(cr.data)

				if x509Valid || (s == SSL3_MT_SERVER_DONE) || (s == SSL3_MT_CERTIFICATE_REQUEST) {
			//		fmt.Println("BREAKING OUT OF LOOP 1")
					dChan <- true
					dChan2 <- true
			//		fmt.Println("BREAKING OUT OF LOOP 2")
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

	// fmt.Println("WAITING; ndone = ", ndone)
	for ndone < 2 {
	//	fmt.Println("WAITING; ndone = ", ndone)
		select {
		case cr := <-crChan:
			// fmt.Printf("CHAN DATA: %v, %v, %v\n", cr.client, cr.err, len(cr.data))
			if cr.err != nil || cr.data == nil {
				ndone++
			} else if cr.client {
				conn2.Write(cr.data)
			} else if !cr.client {
				conn.Write(cr.data)
			}

		}
	}

	// fmt.Println("______ ndone = 2\n")

	//	dChan <- true
	//close(dChan)
	//close(dChan2)

	if !x509Valid {
		return errors.New("Unknown error: TLS connection could not be validated")
	}

	return nil

}
