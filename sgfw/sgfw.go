package sgfw

import (
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/op/go-logging"

	"github.com/subgraph/fw-daemon/nfqueue"
	"github.com/subgraph/go-procsnitch"
)

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

var commentRegexp = regexp.MustCompile("^[ \t]*#")

func Main() {
	readConfig()
	logBackend := setupLoggerBackend(FirewallConfig.LoggingLevel)
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
		dns:             newDNSCache(),
		enabled:         true,
		logBackend:      logBackend,
		policyMap:       make(map[string]*Policy),
		reloadRulesChan: make(chan bool, 0),
		stopChan:        make(chan bool, 0),
	}
	ds.fw = fw

	fw.loadRules()

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
