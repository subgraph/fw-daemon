package main

import (
	"bufio"
	"bytes"
	"fmt"
	"golang.org/x/net/proxy"
	"net"
	"strings"
	"sync"
	"testing"
)

type AccumulatingService struct {
	net, address    string
	buffer          bytes.Buffer
	mortalService   *MortalService
	hasProtocolInfo bool
	hasAuthenticate bool
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

func (a *AccumulatingService) SessionWorker(conn net.Conn) error {
	connReader := bufio.NewReader(conn)
	for {

		line, err := connReader.ReadBytes('\n')
		if err != nil {
			fmt.Println("AccumulatingService read error:", err)
		}
		lineStr := strings.TrimSpace(string(line))
		a.buffer.WriteString(lineStr + "\n")
	}
	return nil
}

func TestSocksServerProxyChain(t *testing.T) {
	socksConfig := SocksChainConfig{
		TargetSocksNet:  "tcp",
		TargetSocksAddr: "127.0.0.1:9050",
		ListenSocksNet:  "tcp",
		ListenSocksAddr: "127.0.0.1:8850",
	}
	wg := sync.WaitGroup{}
	InitSocksListener(&socksConfig, &wg)

	auth := proxy.Auth{
		User:     "",
		Password: "",
	}
	forward := proxy.NewPerHost(proxy.Direct, proxy.Direct)

	terminatingService := NewAccumulatingService("tcp", "127.0.0.1:1234")
	terminatingService.Start()

	socksClient, err := proxy.SOCKS5("tcp", "127.0.0.1:8850", &auth, forward)
	conn, err := socksClient.Dial("tcp", "127.0.0.1:1234")

	if err != nil {
		panic(err)
	}

	rd := bufio.NewReader(conn)
	line := []byte{}
	line, err = rd.ReadBytes('\n')
	if err != nil {
		panic(err)
	}
	fmt.Println("socks client received", string(line))

	wg.Wait()
}
