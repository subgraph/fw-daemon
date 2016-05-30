package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/subgraph/fw-daemon/socks5"
	"golang.org/x/net/proxy"
)

type AccumulatingService struct {
	net, address    string
	buffer          bytes.Buffer
	mortalService   *MortalService
	hasProtocolInfo bool
	hasAuthenticate bool
	receivedChan    chan bool
}

func NewAccumulatingService(net, address string) *AccumulatingService {
	l := AccumulatingService{
		net:             net,
		address:         address,
		hasProtocolInfo: true,
		hasAuthenticate: true,
	}
	return &l
}

func (a *AccumulatingService) Start() {
	a.mortalService = NewMortalService(a.net, a.address, a.SessionWorker)
	a.mortalService.Start()
}

func (a *AccumulatingService) Stop() {
	fmt.Println("AccumulatingService STOP")
	a.mortalService.Stop()
}

func (a *AccumulatingService) WaitUntilReceived() {
	<-a.receivedChan
}

func (a *AccumulatingService) SessionWorker(conn net.Conn) error {
	connReader := bufio.NewReader(conn)
	for {

		line, err := connReader.ReadBytes('\n')
		if err != nil {
			panic(fmt.Sprintf("AccumulatingService read error: %s", err))
		}
		lineStr := strings.TrimSpace(string(line))
		a.buffer.WriteString(lineStr + "\n")
		a.receivedChan <- true
	}
	return nil
}

func fakeSocksSessionWorker(clientConn net.Conn, targetNet, targetAddr string) error {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr()
	fmt.Printf("INFO/socks: New connection from: %v\n", clientAddr)

	// Do the SOCKS handshake with the client, and read the command.
	fmt.Println("meow1")
	req, err := socks5.Handshake(clientConn)
	if err != nil {
		panic(fmt.Sprintf("ERR/socks: Failed SOCKS5 handshake: %v", err))
	}

	var upstreamConn net.Conn
	upstreamConn, err = net.Dial(targetNet, targetAddr)
	if err != nil {
		panic(err)
	}
	fmt.Println("meow2")
	defer upstreamConn.Close()
	req.Reply(socks5.ReplySucceeded)
	fmt.Println("meow3")

	// A upstream connection has been established, push data back and forth
	// till the session is done.
	var wg sync.WaitGroup
	wg.Add(2)

	//upstreamConn.Write([]byte("meow 123\r\n"))
	fmt.Println("meow4")
	copyLoop := func(dst, src net.Conn) {
		defer wg.Done()
		defer dst.Close()

		io.Copy(dst, src)
	}
	go copyLoop(upstreamConn, clientConn)
	go copyLoop(clientConn, upstreamConn)

	fmt.Println("meow5")

	wg.Wait()
	fmt.Printf("INFO/socks: Closed SOCKS connection from: %v\n", clientAddr)
	return nil
}

func TestSocksServerProxyChain(t *testing.T) {
	// socks client ---> socks chain ---> socks server ---> service
	socksChainNet := "tcp"
	socksChainAddr := "127.0.0.1:7750"
	socksServerNet := "tcp"
	socksServerAddr := "127.0.0.1:8850"
	serviceNet := "tcp"
	serviceAddr := "127.0.0.1:9950"

	fmt.Println("foo1")
	// setup the service listener
	service := NewAccumulatingService(serviceNet, serviceAddr)
	service.Start()
	defer service.Stop()

	fmt.Println("foo2")
	// setup the "socks server"
	session := func(clientConn net.Conn) error {
		return fakeSocksSessionWorker(clientConn, serviceNet, serviceAddr)
	}
	socksService := NewMortalService(socksServerNet, socksServerAddr, session)
	socksService.Start()
	defer socksService.Stop()

	fmt.Println("foo3")
	// setup the SOCKS proxy chain
	socksConfig := SocksChainConfig{
		TargetSocksNet:  socksServerNet,
		TargetSocksAddr: socksServerAddr,
		ListenSocksNet:  socksChainNet,
		ListenSocksAddr: socksChainAddr,
	}
	wg := sync.WaitGroup{}
	InitSocksListener(&socksConfig, &wg)

	fmt.Println("foo4")
	// setup the SOCKS client
	auth := proxy.Auth{
		User:     "",
		Password: "",
	}
	forward := proxy.NewPerHost(proxy.Direct, proxy.Direct)
	socksClient, err := proxy.SOCKS5(socksChainNet, socksChainAddr, &auth, forward)
	conn, err := socksClient.Dial(serviceNet, serviceAddr)
	if err != nil {
		panic(err)
	}

	fmt.Println("foo5")
	conn.Write([]byte("meow 123\r\n"))
	service.WaitUntilReceived()
	fmt.Println("DATA RECEIVED", service.buffer.String())
	fmt.Println("foo6")
	// read a banner from the service
	//rd := bufio.NewReader(conn)
	//line := []byte{}
	//line, err = rd.ReadBytes('\n')
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("socks client received", string(line))

	//wg.Wait()
}
