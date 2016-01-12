package main

import (
	// _ "net/http/pprof"
	"os"
	"os/signal"
	"time"

	"github.com/subgraph/fw-daemon/Godeps/_workspace/src/github.com/op/go-logging"
	"github.com/subgraph/fw-daemon/nfqueue"
	"sync"
	"syscall"
	"unsafe"
)

var log = logging.MustGetLogger("sgfw")

var logFormat = logging.MustStringFormatter(
	"%{level:.4s} %{id:03x} %{message}",
)
var ttyFormat = logging.MustStringFormatter(
	"%{color}%{time:15:04:05} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)
const ioctlReadTermios = 0x5401

func isTerminal(fd int) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), ioctlReadTermios, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}

func init() {
	format := logFormat
	if isTerminal(int(os.Stderr.Fd())) {
		format = ttyFormat
	}
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	log.SetBackend(leveler)
}

type Firewall struct {
	dbus *dbusServer
	dns  *dnsCache

	lock      sync.Mutex
	policyMap map[string]*Policy
	policies  []*Policy
}

func (fw *Firewall) runFilter() {
	q := nfqueue.NewNFQueue(0)
	defer q.Destroy()

	q.DefaultVerdict = nfqueue.DROP
	q.Timeout = 5 * time.Minute
	packets := q.Process()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill)

	for {
		select {
		case pkt := <-packets:
			fw.filterPacket(pkt)
		case <-sigs:
			return
		}
	}
}

func main() {

	if os.Geteuid() != 0 {
		log.Error("Must be run as root")
		os.Exit(1)
	}

	setupIPTables()

	ds, err := newDbusServer()
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	fw := &Firewall{
		dbus:      ds,
		dns:       NewDnsCache(),
		policyMap: make(map[string]*Policy),
	}

	fw.loadRules()

	/*
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()
	*/

	fw.runFilter()
}
