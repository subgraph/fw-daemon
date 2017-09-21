package sgfw

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/subgraph/go-procsnitch"
	"strconv"
	"strings"
)

type socksChainConfig struct {
	TargetSocksNet  string
	TargetSocksAddr string
	ListenSocksNet  string
	ListenSocksAddr string
	Name            string
}

type socksChain struct {
	cfg      *socksChainConfig
	fw       *Firewall
	listener net.Listener
	wg       *sync.WaitGroup
	procInfo procsnitch.ProcInfo
}

type socksChainSession struct {
	cfg          *socksChainConfig
	clientConn   net.Conn
	upstreamConn net.Conn
	req          *Request
	bndAddr      *Address
	optData      []byte
	procInfo     procsnitch.ProcInfo
	pinfo        *procsnitch.Info
	server       *socksChain
}

const (
	socksVerdictDrop          = 1
	socksVerdictAccept        = 2
	socksVerdictAcceptTLSOnly = 3
)

type pendingSocksConnection struct {
	pol        *Policy
	hname      string
	srcIP      net.IP
	destIP     net.IP
	sourcePort uint16
	destPort   uint16
	pinfo      *procsnitch.Info
	verdict    chan int
	prompting  bool
	optstr     string
}

func (sc *pendingSocksConnection) sandbox() string {
	return sc.pinfo.Sandbox
}

func (sc *pendingSocksConnection) socks() bool {
	return true
}

func (sc *pendingSocksConnection) policy() *Policy {
	return sc.pol
}

func (sc *pendingSocksConnection) procInfo() *procsnitch.Info {
	return sc.pinfo
}

func (sc *pendingSocksConnection) getOptString() string {
	return sc.optstr
}

func (sc *pendingSocksConnection) hostname() string {
	return sc.hname
}

func (sc *pendingSocksConnection) dst() net.IP {
	return sc.destIP
}
func (sc *pendingSocksConnection) proto() string {
	return "tcp"
}
func (sc *pendingSocksConnection) srcPort() uint16 {
	return sc.sourcePort
}
func (sc *pendingSocksConnection) dstPort() uint16 {
	return sc.destPort
}

func (sc *pendingSocksConnection) src() net.IP {
	return sc.srcIP
}

func (sc *pendingSocksConnection) deliverVerdict(v int) {
	defer func() {
		if r := recover(); r != nil {
			log.Warning("SOCKS5 server recovered from panic while delivering firewall verdict:", r)
		}
	}()

	sc.verdict <- v
	close(sc.verdict)
}

func (sc *pendingSocksConnection) accept() { sc.deliverVerdict(socksVerdictAccept) }

// need to generalize special accept

func (sc *pendingSocksConnection) acceptTLSOnly() { sc.deliverVerdict(socksVerdictAcceptTLSOnly) }

func (sc *pendingSocksConnection) drop() { sc.deliverVerdict(socksVerdictDrop) }

func (sc *pendingSocksConnection) getPrompting() bool { return sc.prompting }

func (sc *pendingSocksConnection) setPrompting(val bool) { sc.prompting = val }

func (sc *pendingSocksConnection) print() string { return "socks connection" }

func NewSocksChain(cfg *socksChainConfig, wg *sync.WaitGroup, fw *Firewall) *socksChain {
	chain := socksChain{
		cfg:      cfg,
		fw:       fw,
		wg:       wg,
		procInfo: procsnitch.SystemProcInfo{},
	}
	return &chain
}

// Start initializes the SOCKS 5 server and starts
// accepting connections.
func (s *socksChain) start() {
	var err error
	s.listener, err = net.Listen(s.cfg.ListenSocksNet, s.cfg.ListenSocksAddr)
	if err != nil {
		log.Errorf("ERR/socks: Failed to listen on the socks address: %v", err)
		os.Exit(1)
	}

	s.wg.Add(1)
	go s.socksAcceptLoop()
}

func (s *socksChain) socksAcceptLoop() error {
	defer s.wg.Done()
	defer s.listener.Close()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				log.Infof("ERR/socks: Failed to Accept(): %v", err)
				return err
			}
			continue
		}
		session := &socksChainSession{cfg: s.cfg, clientConn: conn, procInfo: s.procInfo, server: s}
		go session.sessionWorker()
	}
}

func (c *socksChainSession) sessionWorker() {
	defer c.clientConn.Close()

	clientAddr := c.clientConn.RemoteAddr()
	log.Infof("INFO/socks: New connection from: %v", clientAddr)

	// Do the SOCKS handshake with the client, and read the command.
	var err error
	if c.req, err = Handshake(c.clientConn); err != nil {
		log.Infof("ERR/socks: Failed SOCKS5 handshake: %v", err)
		return
	}

	if len(c.req.Auth.Uname) == 0 && len(c.req.Auth.Passwd) == 0 {
		// Randomize username and password to force a new TOR circuit with each connection
		rndbytes := []byte("sgfw" + strconv.Itoa(int(time.Now().UnixNano())^os.Getpid()))
		c.req.Auth.Uname = rndbytes
		c.req.Auth.Passwd = rndbytes
	}

	switch c.req.Cmd {
	case CommandTorResolve, CommandTorResolvePTR:
		err = c.dispatchTorSOCKS()

		// If we reach here, the request has been dispatched and completed.
		if err == nil {
			// Successfully even, send the response back with the address.
			c.req.ReplyAddr(ReplySucceeded, c.bndAddr)
		}
	case CommandConnect:
		verdict, tls := c.filterConnect()

		if !verdict {
			c.req.Reply(ReplyConnectionRefused)
			return
		}
		c.handleConnect(tls)
	default:
		// Should *NEVER* happen, validated as part of handshake.
		log.Infof("BUG/socks: Unsupported SOCKS command: 0x%02x", c.req.Cmd)
		c.req.Reply(ReplyCommandNotSupported)
	}
}

func (c *socksChainSession) addressDetails() (string, net.IP, uint16) {
	addr := c.req.Addr
	host, pstr := addr.HostPort()
	port, err := strconv.ParseUint(pstr, 10, 16)
	if err != nil || port == 0 || port > 0xFFFF {
		log.Warningf("Illegal port value in socks address: %v", addr)
		return "", nil, 0
	}
	if addr.Type() == 3 {
		return host, nil, uint16(port)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		log.Warningf("Failed to extract address information from socks address: %v", addr)
	}
	return "", ip, uint16(port)
}

func findProxyEndpoint(pdata []string, conn net.Conn) (*procsnitch.Info, string) {
	for _, pstr := range pdata {
		toks := strings.Split(pstr, " ")

		if len(toks) != 6 {
			continue
		}

		s1, d1, s2, d2 := toks[0], toks[2], toks[3], toks[5]

		if strings.HasSuffix(d1, ",") {
			d1 = d1[0 : len(d1)-1]
		}

		if conn.LocalAddr().String() == d2 && conn.RemoteAddr().String() == s2 {
			srcips, srcps, err := net.SplitHostPort(s1)
			dstips, dstps, err2 := net.SplitHostPort(d1)

			if err != nil && err2 != nil {
				continue
			}

			srcip := net.ParseIP(srcips)
			dstip := net.ParseIP(dstips)

			if srcip == nil || dstip == nil {
				continue
			}

			srcport, err := strconv.Atoi(srcps)
			dstport, err2 := strconv.Atoi(dstps)

			if err != nil || err2 != nil {
				continue
			}

			res := procsnitch.LookupTCPSocketProcessAll(srcip, uint16(srcport), dstip, uint16(dstport), nil)
			res, optstr := LookupSandboxProc(srcip, uint16(srcport), dstip, uint16(dstport), "tcp", procsnitch.MATCH_STRICT, 0)

			if res != nil {
				return res, optstr
			}
		}

	}

	return nil, ""
}

func (c *socksChainSession) filterConnect() (bool, bool) {
	// return filter verdict, tlsguard

	allProxies, err := ListProxies()
	var pinfo *procsnitch.Info = nil
	var optstr = ""

	// try to find process via oz-daemon known proxy endpoints

	if err == nil {
		pinfo, optstr = findProxyEndpoint(allProxies, c.clientConn)
	}

	// fall back to system-wide processes

	if pinfo == nil {
		pinfo = procsnitch.FindProcessForConnection(c.clientConn, c.procInfo)

	}

	// connection maybe doesn't exist anymore

	if pinfo == nil {
		log.Warningf("No proc found for [socks5] connection from: %s", c.clientConn.RemoteAddr())
		return false, false
	}

	c.pinfo = pinfo

	if optstr == "" {
		optstr = "Via SOCKS5: " + c.cfg.Name
	} else {
		optstr = "[Via SOCKS5: " + c.cfg.Name + "] " + optstr
	}

	policy := c.server.fw.PolicyForPathAndSandbox(GetRealRoot(pinfo.ExePath, pinfo.Pid), pinfo.Sandbox)

	hostname, ip, port := c.addressDetails()
	if ip == nil && hostname == "" {
		return false, false
	}
	result := policy.rules.filter(nil, nil, ip, port, hostname, pinfo, optstr)
	switch result {
	case FILTER_DENY:
		return false, false
	case FILTER_ALLOW:
		return true, false
	case FILTER_ALLOW_TLSONLY:
		return true, true
	case FILTER_PROMPT:
		caddr := c.clientConn.RemoteAddr().String()
		caddrt := strings.Split(caddr, ":")
		caddrIP := net.IP{0, 0, 0, 0}
		caddrPort := uint16(0)

		if len(caddrt) != 2 {
			log.Errorf("Error reading peer information from SOCKS client connection")
		} else {
			srcp, err := strconv.Atoi(caddrt[1])

			if err != nil || srcp <= 0 || srcp > 65535 {
				log.Errorf("Error getting port of SOCKS client connection")
			} else {
				caddrPort = uint16(srcp)
				ip := net.ParseIP(caddrt[0])

				if ip == nil {
					log.Errorf("Error getting host IP of SOCKS5 client connection: %v", err)
				} else {
					caddrIP = ip
				}

			}

		}

		pending := &pendingSocksConnection{
			pol:        policy,
			hname:      hostname,
			destIP:     ip,
			srcIP:      caddrIP,
			sourcePort: caddrPort,
			destPort:   port,
			pinfo:      pinfo,
			verdict:    make(chan int),
			prompting:  false,
			optstr:     optstr,
		}
		policy.processPromptResult(pending)
		v := <-pending.verdict
		if v == socksVerdictAccept {
			return true, false
		} else if v == socksVerdictAcceptTLSOnly {
			return true, true
		}
	}

	return false, false

}

func (c *socksChainSession) handleConnect(tls bool) {
	err := c.dispatchTorSOCKS()
	if err != nil {
		return
	}
	c.req.Reply(ReplySucceeded)
	defer c.upstreamConn.Close()

	if c.optData != nil {
		if _, err = c.upstreamConn.Write(c.optData); err != nil {
			log.Infof("ERR/socks: Failed writing OptData: %v", err)
			return
		}
		c.optData = nil
	}

	// A upstream connection has been established, push data back and forth
	// till the session is done.
	c.forwardTraffic(tls)
	log.Infof("INFO/socks: Closed SOCKS connection from: %v", c.clientConn.RemoteAddr())
}

func (c *socksChainSession) forwardTraffic(tls bool) {
	if tls == true {
		err := TLSGuard(c.clientConn, c.upstreamConn, c.req.Addr.addrStr)

		if err != nil {
			if c.pinfo.Sandbox != "" {
				log.Errorf("TLSGuard violation: Dropping traffic from %s (sandbox: %s) to %s: %v", c.pinfo.ExePath, c.pinfo.Sandbox, c.req.Addr.addrStr, err)
			} else {
				log.Errorf("TLSGuard violation: Dropping traffic from %s (unsandboxed) to %s: %v", c.pinfo.ExePath, c.req.Addr.addrStr, err)
			}
			return
		} else {
			log.Notice("TLSGuard approved certificate presented for connection to: ", c.req.Addr.addrStr)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	copyLoop := func(dst, src net.Conn) {
		defer wg.Done()
		defer dst.Close()

		io.Copy(dst, src)
	}
	go copyLoop(c.upstreamConn, c.clientConn)
	go copyLoop(c.clientConn, c.upstreamConn)

	wg.Wait()
}

func (c *socksChainSession) dispatchTorSOCKS() (err error) {
	c.upstreamConn, c.bndAddr, err = Redispatch(c.cfg.TargetSocksNet, c.cfg.TargetSocksAddr, c.req)
	if err != nil {
		c.req.Reply(ErrorToReplyCode(err))
	}
	return
}
