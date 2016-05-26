package main

import (
	"io"
	"net"
	"os"
	"sync"

	"github.com/subgraph/fw-daemon/socks5"
)

type SocksChainConfig struct {
	TargetSocksNet  string
	TargetSocksAddr string
	ListenSocksNet  string
	ListenSocksAddr string
}

type session struct {
	cfg *SocksChainConfig

	clientConn   net.Conn
	upstreamConn net.Conn

	req     *socks5.Request
	bndAddr *socks5.Address
	optData []byte
}

// InitSocksListener initializes the SOCKS 5 server and starts
// accepting connections.
func InitSocksListener(cfg *SocksChainConfig, wg *sync.WaitGroup) {
	ln, err := net.Listen(cfg.ListenSocksNet, cfg.ListenSocksAddr)
	if err != nil {
		log.Error("ERR/socks: Failed to listen on the socks address: %v", err)
		os.Exit(1)
	}

	wg.Add(1)
	go socksAcceptLoop(cfg, ln, wg)
}

func socksAcceptLoop(cfg *SocksChainConfig, ln net.Listener, wg *sync.WaitGroup) error {
	defer wg.Done()
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				log.Info("ERR/socks: Failed to Accept(): %v", err)
				return err
			}
			continue
		}
		s := &session{cfg: cfg, clientConn: conn}
		go s.sessionWorker()
	}
}

func (s *session) sessionWorker() {
	defer s.clientConn.Close()

	clientAddr := s.clientConn.RemoteAddr()
	log.Info("INFO/socks: New connection from: %v", clientAddr)

	// Do the SOCKS handshake with the client, and read the command.
	var err error
	if s.req, err = socks5.Handshake(s.clientConn); err != nil {
		log.Info("ERR/socks: Failed SOCKS5 handshake: %v", err)
		return
	}

	switch s.req.Cmd {
	case socks5.CommandTorResolve, socks5.CommandTorResolvePTR:
		err = s.dispatchTorSOCKS()

		// If we reach here, the request has been dispatched and completed.
		if err == nil {
			// Successfully even, send the response back with the address.
			s.req.ReplyAddr(socks5.ReplySucceeded, s.bndAddr)
		}
		return
	case socks5.CommandConnect:
	default:
		// Should *NEVER* happen, validated as part of handshake.
		log.Info("BUG/socks: Unsupported SOCKS command: 0x%02x", s.req.Cmd)
		s.req.Reply(socks5.ReplyCommandNotSupported)
		return
	}

	err = s.dispatchTorSOCKS()
	if err != nil {
		return
	}
	s.req.Reply(socks5.ReplySucceeded)
	defer s.upstreamConn.Close()

	if s.optData != nil {
		if _, err = s.upstreamConn.Write(s.optData); err != nil {
			log.Info("ERR/socks: Failed writing OptData: %v", err)
			return
		}
		s.optData = nil
	}

	// A upstream connection has been established, push data back and forth
	// till the session is done.
	var wg sync.WaitGroup
	wg.Add(2)

	copyLoop := func(dst, src net.Conn) {
		defer wg.Done()
		defer dst.Close()

		io.Copy(dst, src)
	}
	go copyLoop(s.upstreamConn, s.clientConn)
	go copyLoop(s.clientConn, s.upstreamConn)

	wg.Wait()
	log.Info("INFO/socks: Closed SOCKS connection from: %v", clientAddr)
}

func (s *session) dispatchTorSOCKS() (err error) {
	s.upstreamConn, s.bndAddr, err = socks5.Redispatch(s.cfg.TargetSocksNet, s.cfg.TargetSocksAddr, s.req)
	if err != nil {
		s.req.Reply(socks5.ErrorToReplyCode(err))
	}
	return
}
