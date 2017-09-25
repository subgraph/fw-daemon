package sgfw

import (
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	//	"time"
	"bufio"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/op/go-logging"
	nfqueue "github.com/subgraph/go-nfnetlink/nfqueue"
	//	"github.com/subgraph/go-nfnetlink"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/subgraph/fw-daemon/proc-coroner"
	"github.com/subgraph/go-procsnitch"
)

var dbusp *dbusObjectP = nil

type Firewall struct {
	dbus *dbusServer
	dns  *dnsCache

	enabled bool

	logBackend logging.LeveledBackend

	lock      sync.Mutex
	policyMap map[string]*Policy
	policies  []*Policy

	ruleLock   sync.Mutex
	rulesByID  map[uint]*Rule
	nextRuleID uint

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
	fw.rulesByID = nil
	fw.nextRuleID = 0
}

func (fw *Firewall) addRule(r *Rule) {
	fw.ruleLock.Lock()
	defer fw.ruleLock.Unlock()

	r.id = fw.nextRuleID
	fw.nextRuleID++
	if fw.rulesByID == nil {
		fw.rulesByID = make(map[uint]*Rule)
	}
	fw.rulesByID[r.id] = r
}

func (fw *Firewall) getRuleByID(id uint) *Rule {
	fw.ruleLock.Lock()
	defer fw.ruleLock.Unlock()

	if fw.rulesByID == nil {
		return nil
	}
	return fw.rulesByID[id]
}

func (fw *Firewall) stop() {
	fw.stopChan <- true
}

func (fw *Firewall) reloadRules() {
	fw.reloadRulesChan <- true
}

func (fw *Firewall) runFilter() {
	q := nfqueue.NewNFQueue(0)

	// XXX: need to implement this
	//	q.DefaultVerdict = nfqueue.DROP
	// XXX: need this as well
	//	q.Timeout = 5 * time.Minute

	ps, err := q.Open()

	if err != nil {
		log.Fatal("Error opening NFQueue:", err)
	}
	q.EnableHWTrace()
	defer q.Close()

	go func() {
		for p := range ps {
			if fw.isEnabled() {
				ipLayer := p.Packet.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					continue
				}

				ip, _ := ipLayer.(*layers.IPv4)
				if ip == nil {
					continue
				}

				if ip.Version == 6 {
					ip6p := gopacket.NewPacket(ip.LayerContents(), layers.LayerTypeIPv6, gopacket.Default)
					p.Packet = ip6p

				}

				fw.filterPacket(p)
			} else {
				p.Accept()
			}
		}
	}()

	for {
		select {
		case <-fw.reloadRulesChan:
			fw.loadRules()
		case <-fw.stopChan:
			return
		}
	}
}

type SocksJsonConfig struct {
	Name          string
	SocksListener string
	TorSocks      string
}

var commentRegexp = regexp.MustCompile("^[ \t]*#")

const defaultSocksCfgPath = "/etc/sgfw/fw-daemon-socks.json"

func loadSocksConfiguration(configFilePath string) (*SocksJsonConfig, error) {
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
	// TODO: fix this to support multiple named proxy forwarders of different types
	fields := strings.Split(config.TorSocks, "|")
	torSocksNet := fields[0]
	torSocksAddr := fields[1]
	fields = strings.Split(config.SocksListener, "|")
	socksListenNet := fields[0]
	socksListenAddr := fields[1]
	socksConfig := socksChainConfig{
		Name:            config.Name,
		TargetSocksNet:  torSocksNet,
		TargetSocksAddr: torSocksAddr,
		ListenSocksNet:  socksListenNet,
		ListenSocksAddr: socksListenAddr,
	}
	log.Notice("Loaded Socks chain config:")
	log.Notice(socksConfig)
	return &socksConfig
}

func Main() {
	readConfig()
	logBackend, logBackend2 := setupLoggerBackend(FirewallConfig.LoggingLevel)

	if logBackend2 == nil {
		logging.SetBackend(logBackend)
	} else {
		logging.SetBackend(logBackend, logBackend2)
	}

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
		dns:             newDNSCache(),
		enabled:         true,
		logBackend:      logBackend,
		policyMap:       make(map[string]*Policy),
		reloadRulesChan: make(chan bool, 0),
		stopChan:        make(chan bool, 0),
	}
	ds.fw = fw
	go pcoroner.MonitorThread(procDeathCallbackDNS, fw.dns)

	fw.loadRules()

	/*
	   go func() {
	           http.ListenAndServe("localhost:6060", nil)
	   }()
	*/

	wg := sync.WaitGroup{}

	scfile := os.Getenv("SGFW_SOCKS_CONFIG")

	if scfile == "" {
		scfile = defaultSocksCfgPath
	}

	config, err := loadSocksConfiguration(scfile)
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	if config != nil {
		socksConfig := getSocksChainConfig(config)
		chain := NewSocksChain(socksConfig, &wg, fw)
		chain.start()
	} else {
		log.Notice("Did not find SOCKS5 configuration file at", scfile, "; ignoring subsystem...")
	}

	dbusp, err = newDbusObjectPrompt()
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to dbus system bus for sgfw prompt events: %v", err))
	}

	dbusp.alertRule("fw-daemon initialization")

	go OzReceiver(fw)

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
		case <-sigKillChan:
			fw.stop()
			return
		}
	}
}
