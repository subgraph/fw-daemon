package main

import (
	"fmt"
	"net"
	"sync"
	"time"
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
	log.Info("stopping listener service %s:%s", l.network, l.address)
	close(l.quit)
	if l.listener != nil {
		l.listener.Close()
	}
	l.waitGroup.Wait()
}

func (l *MortalService) acceptLoop() {
	defer l.waitGroup.Done()
	defer func() {
		log.Info("stoping listener service %s:%s", l.network, l.address)
		for i, conn := range l.conns {
			if conn != nil {
				log.Info("Closing connection #%d", i)
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
				log.Info("MortalService connection accept failure: %s\n", err)
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
		log.Info("Closing connection #%d", id)
		conn.Close()
		l.conns[id] = nil
	}()

	log.Info("Starting connection #%d", id)

	for {
		if err := l.connectionCallback(conn); err != nil {
			log.Error(err.Error())
			return err
		}
		return nil
	}
}
