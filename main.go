package main

import (
	// _ "net/http/pprof"
	"bufio"
	"encoding/json"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/subgraph/fw-daemon/nfqueue"
	"github.com/subgraph/go-procsnitch"
	"github.com/op/go-logging"
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

func setupLoggerBackend() logging.LeveledBackend {
	format := logFormat
	if isTerminal(int(os.Stderr.Fd())) {
		format = ttyFormat
	}
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	leveler.SetLevel(logging.NOTICE, "sgfw")
	return leveler
}

var logRedact bool

type Firewall struct {
	dbus *dbusServer
	dns  *dnsCache

	enabled bool

	logBackend logging.LeveledBackend

	lock      sync.Mutex
	policyMap map[string]*Policy
	policies  []*Policy

	ruleLock   sync.Mutex
	rulesById  map[uint]*Rule
	nextRuleId uint

	reloadRulesChan chan bool
	stopChan        chan bool
}

func (fw *Firewall) setEnabled(flag bool) {
	fw.lock.Lock()
	defer fw.lock.Unlock()
	fw.enabled = flag
}

func (fw *Firewall) isEnabled() bool {
	fw.lock.Lock()
	defer fw.lock.Unlock()
	return fw.enabled
}

func (fw *Firewall) clearRules() {
	fw.ruleLock.Lock()
	defer fw.ruleLock.Unlock()
	fw.rulesById = nil
	fw.nextRuleId = 0
}

func (fw *Firewall) addRule(r *Rule) {
	fw.ruleLock.Lock()
	defer fw.ruleLock.Unlock()

	r.id = fw.nextRuleId
	fw.nextRuleId += 1
	if fw.rulesById == nil {
		fw.rulesById = make(map[uint]*Rule)
	}
	fw.rulesById[r.id] = r
}

func (fw *Firewall) getRuleById(id uint) *Rule {
	fw.ruleLock.Lock()
	defer fw.ruleLock.Unlock()

	if fw.rulesById == nil {
		return nil
	}
	return fw.rulesById[id]
}

func (fw *Firewall) stop() {
	fw.stopChan <- true
}

func (fw *Firewall) reloadRules() {
	fw.reloadRulesChan <- true
}

func (fw *Firewall) runFilter() {
	q := nfqueue.NewNFQueue(0)
	defer q.Destroy()

	q.DefaultVerdict = nfqueue.DROP
	q.Timeout = 5 * time.Minute
	packets := q.Process()

	for {
		select {
		case pkt := <-packets:
			if fw.isEnabled() {
				fw.filterPacket(pkt)
			} else {
				pkt.Accept()
			}
		case <-fw.reloadRulesChan:
			fw.loadRules()
		case <-fw.stopChan:
			return
		}
	}
}

type SocksJsonConfig struct {
	SocksListener string
	TorSocks      string
}

var commentRegexp = regexp.MustCompile("^[ \t]*#")

func loadConfiguration(configFilePath string) (*SocksJsonConfig, error) {
	config := SocksJsonConfig{}
	file, err := os.Open(configFilePath)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	bs := ""
	for scanner.Scan() {
		line := scanner.Text()
		if !commentRegexp.MatchString(line) {
			bs += line + "\n"
		}
	}
	if err := json.Unmarshal([]byte(bs), &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func getSocksChainConfig(config *SocksJsonConfig) *socksChainConfig {
	// XXX
	fields := strings.Split(config.TorSocks, "|")
	torSocksNet := fields[0]
	torSocksAddr := fields[1]
	fields = strings.Split(config.SocksListener, "|")
	socksListenNet := fields[0]
	socksListenAddr := fields[1]
	socksConfig := socksChainConfig{
		TargetSocksNet:  torSocksNet,
		TargetSocksAddr: torSocksAddr,
		ListenSocksNet:  socksListenNet,
		ListenSocksAddr: socksListenAddr,
	}
	return &socksConfig
}

func main() {
	// XXX should this really be hardcoded?
	// or should i add a CLI to specify config file location?
	config, err := loadConfiguration("/etc/fw-daemon-socks.json")
	if err != nil {
		panic(err)
	}
	socksConfig := getSocksChainConfig(config)

	logBackend := setupLoggerBackend()
	log.SetBackend(logBackend)
	procsnitch.SetLogger(log)

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
		dbus:            ds,
		dns:             NewDnsCache(),
		enabled:         true,
		logBackend:      logBackend,
		policyMap:       make(map[string]*Policy),
		reloadRulesChan: make(chan bool, 0),
		stopChan:        make(chan bool, 0),
	}
	ds.fw = fw

	fw.loadRules()

	/*
		go func() {
			http.ListenAndServe("localhost:6060", nil)
		}()
	*/

	wg := sync.WaitGroup{}
	chain := NewSocksChain(socksConfig, &wg, fw)
	chain.start()

	fw.runFilter()

	// observe process signals and either
	// reload rules or shutdown firewall service
	sigKillChan := make(chan os.Signal, 1)
	signal.Notify(sigKillChan, os.Interrupt, os.Kill)

	sigHupChan := make(chan os.Signal, 1)
	signal.Notify(sigHupChan, syscall.SIGHUP)

	for {
		select {
		case <-sigHupChan:
			fw.reloadRules()
			// XXX perhaps restart SOCKS proxy chain service with new proxy config specification?
		case <-sigKillChan:
			fw.stop()
			return
		}
	}
}
