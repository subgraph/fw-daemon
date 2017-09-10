package procsnitch

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type TestListener struct {
	network   string
	address   string
	waitGroup *sync.WaitGroup
}

func NewTestListener(network, address string, wg *sync.WaitGroup) *TestListener {
	l := TestListener{
		network:   network,
		address:   address,
		waitGroup: wg,
	}
	return &l
}

func (l *TestListener) AcceptLoop() {
	l.waitGroup.Add(1)
	listener, err := net.Listen(l.network, l.address)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	l.waitGroup.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}

		go l.SessionWorker(conn)
	}
}

func (l *TestListener) SessionWorker(conn net.Conn) {
	for {
		time.Sleep(time.Second * 60)
	}
}

func TestLookupUNIXSocketProcess(t *testing.T) {
	// listen for a connection
	var wg sync.WaitGroup
	network := "unix"
	address := "./testing_socket"
	l := NewTestListener(network, address, &wg)
	go l.AcceptLoop()
	wg.Wait()

	// XXX fix me
	time.Sleep(time.Second * 1)

	// dial a connection
	conn, err := net.Dial(network, address)
	if err != nil {
		panic(err)
	}
	defer os.Remove(address)
	conn.Write([]byte("hello"))
	procInfo := LookupUNIXSocketProcess(address)
	if procInfo == nil {
		t.Error("failured to acquire proc info for unix domain socket")
		t.Fail()
	}
	fmt.Println("Acquired proc info for UNIX domain socket!", procInfo)
}
