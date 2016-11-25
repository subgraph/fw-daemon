package main

import (
	"io"
	"net"
	"os"
	"sync"

	"github.com/subgraph/fw-daemon/socks5"
	"github.com/subgraph/go-procsnitch"
	"strconv"
)

type socksChainConfig struct {
	TargetSocksNet  string
	TargetSocksAddr string
	ListenSocksNet  string
	ListenSocksAddr string
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
	req          *socks5.Request
	bndAddr      *socks5.Address
	optData      []byte
	procInfo     procsnitch.ProcInfo
	server       *socksChain
}

const (
	socksVerdictDrop   = 1
	socksVerdictAccept = 2
)

type pendingSocksConnection struct {
	pol      *Policy
	hname    string
	destIP   net.IP
	destPort uint16
	pinfo    *procsnitch.Info
	verdict  chan int
}

func (sc *pendingSocksConnection) policy() *Policy {
	return sc.pol
}

func (sc *pendingSocksConnection) procInfo() *procsnitch.Info {
	return sc.pinfo
}

func (sc *pendingSocksConnection) hostname() string {
	return sc.hname
}

func (sc *pendingSocksConnection) dst() net.IP {
	return sc.destIP
}
func (sc *pendingSocksConnection) dstPort() uint16 {
	return sc.destPort
}

func (sc *pendingSocksConnection) deliverVerdict(v int) {
	sc.verdict <- v
	close(sc.verdict)
}

func (sc *pendingSocksConnection) accept() { sc.deliverVerdict(socksVerdictAccept) }

func (sc *pendingSocksConnection) drop() { sc.deliverVerdict(socksVerdictDrop) }

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
	if c.req, err = socks5.Handshake(c.clientConn); err != nil {
		log.Infof("ERR/socks: Failed SOCKS5 handshake: %v", err)
		return
	}

	switch c.req.Cmd {
	case socks5.CommandTorResolve, socks5.CommandTorResolvePTR:
		err = c.dispatchTorSOCKS()

		// If we reach here, the request has been dispatched and completed.
		if err == nil {
			// Successfully even, send the response back with the addresc.
			c.req.ReplyAddr(socks5.ReplySucceeded, c.bndAddr)
		}
	case socks5.CommandConnect:
		if !c.filterConnect() {
			c.req.Reply(socks5.ReplyConnectionRefused)
			return
		}
		c.handleConnect()
	default:
		// Should *NEVER* happen, validated as part of handshake.
		log.Infof("BUG/socks: Unsupported SOCKS command: 0x%02x", c.req.Cmd)
		c.req.Reply(socks5.ReplyCommandNotSupported)
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

func (c *socksChainSession) filterConnect() bool {
	pinfo := procsnitch.FindProcessForConnection(c.clientConn, c.procInfo)
	if pinfo == nil {
		log.Warningf("No proc found for connection from: %s", c.clientConn.RemoteAddr())
		return false
	}

	policy := c.server.fw.PolicyForPath(pinfo.ExePath)

	hostname, ip, port := c.addressDetails()
	if ip == nil && hostname == "" {
		return false
	}
	result := policy.rules.filter(nil, ip, port, hostname, pinfo)
	switch result {
	case FILTER_DENY:
		return false
	case FILTER_ALLOW:
		return true
	case FILTER_PROMPT:
		pending := &pendingSocksConnection{
			pol:      policy,
			hname:    hostname,
			destIP:   ip,
			destPort: port,
			pinfo:    pinfo,
			verdict:  make(chan int),
		}
		policy.processPromptResult(pending)
		v := <-pending.verdict
		if v == socksVerdictAccept {
			return true
		}
	}

	return false

}

func (c *socksChainSession) handleConnect() {
	err := c.dispatchTorSOCKS()
	if err != nil {
		return
	}
	c.req.Reply(socks5.ReplySucceeded)
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
	c.forwardTraffic()
	log.Infof("INFO/socks: Closed SOCKS connection from: %v", c.clientConn.RemoteAddr())
}

func (c *socksChainSession) forwardTraffic() {
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
	c.upstreamConn, c.bndAddr, err = socks5.Redispatch(c.cfg.TargetSocksNet, c.cfg.TargetSocksAddr, c.req)
	if err != nil {
		c.req.Reply(socks5.ErrorToReplyCode(err))
	}
	return
}
