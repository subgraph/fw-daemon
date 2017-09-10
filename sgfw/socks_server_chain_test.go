package sgfw

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/subgraph/fw-daemon/socks5"
	"golang.org/x/net/proxy"
)

// MortalService can be killed at any time.
type MortalService struct {
	network            string
	address            string
	connectionCallback func(net.Conn) error

	conns     []net.Conn
	quit      chan bool
	listener  net.Listener
	waitGroup *sync.WaitGroup
}

// NewMortalService creates a new MortalService
func NewMortalService(network, address string, connectionCallback func(net.Conn) error) *MortalService {
	l := MortalService{
		network:            network,
		address:            address,
		connectionCallback: connectionCallback,

		conns:     make([]net.Conn, 0, 10),
		quit:      make(chan bool),
		waitGroup: &sync.WaitGroup{},
	}
	return &l
}

// Stop will kill our listener and all it's connections
func (l *MortalService) Stop() {
	log.Infof("stopping listener service %s:%s", l.network, l.address)
	close(l.quit)
	if l.listener != nil {
		l.listener.Close()
	}
	l.waitGroup.Wait()
}

func (l *MortalService) acceptLoop() {
	defer l.waitGroup.Done()
	defer func() {
		log.Infof("stoping listener service %s:%s", l.network, l.address)
		for i, conn := range l.conns {
			if conn != nil {
				log.Infof("Closing connection #%d", i)
				conn.Close()
			}
		}
	}()
	defer l.listener.Close()

	for {
		conn, err := l.listener.Accept()
		if nil != err {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			} else {
				log.Infof("MortalService connection accept failure: %s\n", err)
				select {
				case <-l.quit:
					return
				default:
				}
				continue
			}
		}

		l.conns = append(l.conns, conn)
		go l.handleConnection(conn, len(l.conns)-1)
	}
}

func (l *MortalService) createDeadlinedListener() error {
	if l.network == "tcp" {
		tcpAddr, err := net.ResolveTCPAddr("tcp", l.address)
		if err != nil {
			return fmt.Errorf("MortalService.createDeadlinedListener %s %s failure: %s", l.network, l.address, err)
		}
		tcpListener, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return fmt.Errorf("MortalService.createDeadlinedListener %s %s failure: %s", l.network, l.address, err)
		}
		tcpListener.SetDeadline(time.Now().Add(1e9))
		l.listener = tcpListener
		return nil
	} else if l.network == "unix" {
		unixAddr, err := net.ResolveUnixAddr("unix", l.address)
		if err != nil {
			return fmt.Errorf("MortalService.createDeadlinedListener %s %s failure: %s", l.network, l.address, err)
		}
		unixListener, err := net.ListenUnix("unix", unixAddr)
		if err != nil {
			return fmt.Errorf("MortalService.createDeadlinedListener %s %s failure: %s", l.network, l.address, err)
		}
		unixListener.SetDeadline(time.Now().Add(1e9))
		l.listener = unixListener
		return nil
	} else {
		panic("")
	}
	return nil
}

// Start the MortalService
func (l *MortalService) Start() error {
	var err error
	err = l.createDeadlinedListener()
	if err != nil {
		return err
	}
	l.waitGroup.Add(1)
	go l.acceptLoop()
	return nil
}

func (l *MortalService) handleConnection(conn net.Conn, id int) error {
	defer func() {
		log.Infof("Closing connection #%d", id)
		conn.Close()
		l.conns[id] = nil
	}()

	log.Infof("Starting connection #%d", id)

	for {
		if err := l.connectionCallback(conn); err != nil {
			log.Error(err.Error())
			return err
		}
		return nil
	}
}

type AccumulatingService struct {
	net, address    string
	banner          string
	buffer          bytes.Buffer
	mortalService   *MortalService
	hasProtocolInfo bool
	hasAuthenticate bool
	receivedChan    chan bool
}

func NewAccumulatingService(net, address, banner string) *AccumulatingService {
	l := AccumulatingService{
		net:             net,
		address:         address,
		banner:          banner,
		hasProtocolInfo: true,
		hasAuthenticate: true,
		receivedChan:    make(chan bool, 0),
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
	conn.Write([]byte(a.banner))
	for {
		line, err := connReader.ReadBytes('\n')
		if err != nil {
			fmt.Printf("AccumulatingService read error: %s\n", err)
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
	req, err := socks5.Handshake(clientConn)
	if err != nil {
		panic(fmt.Sprintf("ERR/socks: Failed SOCKS5 handshake: %v", err))
	}

	var upstreamConn net.Conn
	upstreamConn, err = net.Dial(targetNet, targetAddr)
	if err != nil {
		panic(err)
	}
	defer upstreamConn.Close()
	req.Reply(socks5.ReplySucceeded)

	// A upstream connection has been established, push data back and forth
	// till the session is done.
	var wg sync.WaitGroup
	wg.Add(2)
	copyLoop := func(dst, src net.Conn) {
		defer wg.Done()
		defer dst.Close()

		io.Copy(dst, src)
	}
	go copyLoop(upstreamConn, clientConn)
	go copyLoop(clientConn, upstreamConn)

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

	banner := "meow 123\r\n"
	// setup the service listener
	service := NewAccumulatingService(serviceNet, serviceAddr, banner)
	service.Start()
	defer service.Stop()

	// setup the "socks server"
	session := func(clientConn net.Conn) error {
		return fakeSocksSessionWorker(clientConn, serviceNet, serviceAddr)
	}
	socksService := NewMortalService(socksServerNet, socksServerAddr, session)
	socksService.Start()
	defer socksService.Stop()

	// setup the SOCKS proxy chain
	socksConfig := socksChainConfig{
		TargetSocksNet:  socksServerNet,
		TargetSocksAddr: socksServerAddr,
		ListenSocksNet:  socksChainNet,
		ListenSocksAddr: socksChainAddr,
	}
	wg := sync.WaitGroup{}
	ds := dbusServer{}
	chain := NewSocksChain(&socksConfig, &wg, &ds)
	chain.start()

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

	// read a banner from the service
	rd := bufio.NewReader(conn)
	line := []byte{}
	line, err = rd.ReadBytes('\n')
	if err != nil {
		panic(err)
	}
	if string(line) != banner {
		t.Errorf("Did not receive expected banner. Got %s, wanted %s\n", string(line), banner)
		t.Fail()
	}

	// send the service some data and verify it was received
	clientData := "hello world\r\n"
	conn.Write([]byte(clientData))
	service.WaitUntilReceived()
	if service.buffer.String() != strings.TrimSpace(clientData)+"\n" {
		t.Errorf("Client sent %s but service only received %s\n", "hello world\n", service.buffer.String())
		t.Fail()
	}
}
