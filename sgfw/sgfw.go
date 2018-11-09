package sgfw

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/op/go-logging"
	nfqueue "github.com/subgraph/go-nfnetlink/nfqueue"
	//	"github.com/subgraph/go-nfnetlink"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/subgraph/fw-daemon/proc-coroner"
	"github.com/subgraph/go-procsnitch"
)

var dbLogger *dbusObjectP = nil

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
			timestamp := time.Now()

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

				fw.filterPacket(p, timestamp)
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

	fw.dbus.emitRefresh("init")

	//go OzReceiver(fw)

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
