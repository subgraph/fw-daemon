package sgfw

import (
	"fmt"
	"net"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus"
	"github.com/subgraph/fw-daemon/proc-coroner"
)

var DoMultiPrompt = true

const MAX_PROMPTS = 5

var outstandingPrompts = 0
var promptLock = &sync.Mutex{}

func newPrompter(conn *dbus.Conn) *prompter {
	p := new(prompter)
	p.cond = sync.NewCond(&p.lock)
	p.dbusObj = conn.Object("com.subgraph.FirewallPrompt", "/com/subgraph/FirewallPrompt")
	p.policyMap = make(map[string]*Policy)
	go p.promptLoop()
	return p
}

type prompter struct {
	dbusObj     dbus.BusObject
	lock        sync.Mutex
	cond        *sync.Cond
	policyMap   map[string]*Policy
	policyQueue []*Policy
}

func (p *prompter) prompt(policy *Policy) {
	p.lock.Lock()
	defer p.lock.Unlock()
	_, ok := p.policyMap[policy.sandbox+"|"+policy.path]
	if ok {
		return
	}
	p.policyMap[policy.sandbox+"|"+policy.path] = policy
	log.Debugf("Saving policy key:" + policy.sandbox + "|" + policy.path)
	p.policyQueue = append(p.policyQueue, policy)
	p.cond.Signal()
}

func (p *prompter) promptLoop() {
	p.lock.Lock()
	for {
		// fmt.Println("XXX: promptLoop() outer")
		for p.processNextPacket() {
			// fmt.Println("XXX: promptLoop() inner")
		}
		// fmt.Println("promptLoop() wait")
		p.cond.Wait()
	}
}

func (p *prompter) processNextPacket() bool {
	var pc pendingConnection = nil

	if !DoMultiPrompt {
		pc, _ = p.nextConnection()
		if pc == nil {
			return false
		}
		p.lock.Unlock()
		defer p.lock.Lock()
		p.processConnection(pc)
		return true
	}

	empty := true
	for {
		pc, empty = p.nextConnection()
		// fmt.Println("XXX: processNextPacket() loop; empty = ", empty, " / pc = ", pc)
		if pc == nil && empty {
			return false
		} else if pc == nil {
			continue
		} else if pc != nil {
			break
		}
	}
	p.lock.Unlock()
	defer p.lock.Lock()
	// fmt.Println("XXX: Waiting for prompt lock go...")
	for {
		promptLock.Lock()
		if outstandingPrompts >= MAX_PROMPTS {
			promptLock.Unlock()
			continue
		}

		if pc.getPrompting() {
			log.Debugf("Skipping over already prompted connection")
			promptLock.Unlock()
			continue
		}

		break
	}
	// fmt.Println("XXX: Passed prompt lock!")
	outstandingPrompts++
	// fmt.Println("XXX: Incremented outstanding to ", outstandingPrompts)
	promptLock.Unlock()
	//	if !pc.getPrompting() {
	pc.setPrompting(true)
	go p.processConnection(pc)
	//	}
	return true
}

func processReturn(pc pendingConnection) {
	promptLock.Lock()
	outstandingPrompts--
	// fmt.Println("XXX: Return decremented outstanding to ", outstandingPrompts)
	promptLock.Unlock()
	pc.setPrompting(false)
}

func (p *prompter) processConnection(pc pendingConnection) {
	var scope int32
	var rule string

	if DoMultiPrompt {
		defer processReturn(pc)
	}

	addr := pc.hostname()
	if addr == "" {
		addr = pc.dst().String()
	}
	policy := pc.policy()

	dststr := ""

	if pc.dst() != nil {
		dststr = pc.dst().String()
	} else {
		dststr = addr + " (proxy to resolve)"
	}

	call := p.dbusObj.Call("com.subgraph.FirewallPrompt.RequestPrompt", 0,
		policy.application,
		policy.icon,
		policy.path,
		addr,
		int32(pc.dstPort()),
		dststr,
		pc.src().String(),
		pc.proto(),
		int32(pc.procInfo().UID),
		int32(pc.procInfo().GID),
		uidToUser(pc.procInfo().UID),
		gidToGroup(pc.procInfo().GID),
		int32(pc.procInfo().Pid),
		pc.sandbox(),
		pc.socks(),
		pc.getOptString(),
		FirewallConfig.PromptExpanded,
		FirewallConfig.PromptExpert,
		int32(FirewallConfig.DefaultActionID))
	err := call.Store(&scope, &rule)
	if err != nil {
		log.Warningf("Error sending dbus RequestPrompt message: %v", err)
		policy.removePending(pc)
		pc.drop()
		return
	}

	// the prompt sends:
	// ALLOW|dest or DENY|dest
	//
	// rule string needs to be:
	// VERB|dst|class|uid:gid|sandbox|[src]

	// sometimes there's a src
	// this needs to be re-visited

	toks := strings.Split(rule, "|")
	//verb := toks[0]
	//target := toks[1]
	sandbox := ""

	if len(toks) > 2 {
		sandbox = toks[2]
	}

	tempRule := fmt.Sprintf("%s|%s", toks[0], toks[1])

	if pc.src() != nil && !pc.src().Equal(net.ParseIP("127.0.0.1")) && sandbox != "" {

		//if !strings.HasSuffix(rule, "SYSTEM") && !strings.HasSuffix(rule, "||") {
		//rule += "||"
		//}
		//ule += "|||" + pc.src().String()

		tempRule += "||-1:-1|" + sandbox + "|" + pc.src().String()
	} else {
		tempRule += "||-1:-1|" + sandbox + "|"
	}
	r, err := policy.parseRule(tempRule, false)
	if err != nil {
		log.Warningf("Error parsing rule string returned from dbus RequestPrompt: %v", err)
		policy.removePending(pc)
		pc.drop()
		return
	}
	fscope := FilterScope(scope)
	if fscope == APPLY_SESSION {
		r.mode = RULE_MODE_SESSION
	} else if fscope == APPLY_PROCESS {
		r.mode = RULE_MODE_PROCESS
		r.pid = pc.procInfo().Pid
		pcoroner.MonitorProcess(r.pid)
	}
	if !policy.processNewRule(r, fscope) {
		p.lock.Lock()
		defer p.lock.Unlock()
		p.removePolicy(pc.policy())
	}
	if fscope == APPLY_FOREVER {
		r.mode = RULE_MODE_PERMANENT
		policy.fw.saveRules()
	}
	log.Warningf("Prompt returning rule: %v", tempRule)
	dbusp.alertRule("sgfw prompt added new rule")
}

func (p *prompter) nextConnection() (pendingConnection, bool) {
	for {
		if len(p.policyQueue) == 0 {
			return nil, true
		}
		policy := p.policyQueue[0]
		pc, qempty := policy.nextPending()
		if pc == nil && qempty {
			p.removePolicy(policy)
		} else {
			if pc == nil && !qempty {
				log.Errorf("FIX ME: I NEED TO SLEEP ON A WAKEABLE CONDITION PROPERLY!!")
				time.Sleep(time.Millisecond * 300)
			}
			return pc, qempty
		}
	}
}

func (p *prompter) removePolicy(policy *Policy) {
	var newQueue []*Policy = nil

	if DoMultiPrompt {
		if len(p.policyQueue) == 0 {
			log.Debugf("Skipping over zero length policy queue")
			newQueue = make([]*Policy, 0, 0)
		}
	}

	if !DoMultiPrompt || newQueue == nil {
		newQueue = make([]*Policy, 0, len(p.policyQueue)-1)
	}
	for _, pol := range p.policyQueue {
		if pol != policy {
			newQueue = append(newQueue, pol)
		}
	}
	p.policyQueue = newQueue
	delete(p.policyMap, policy.sandbox+"|"+policy.path)
}

var userMap = make(map[int]string)
var groupMap = make(map[int]string)

func lookupUser(uid int) string {
	if uid == -1 {
		return "[unknown]"
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return fmt.Sprintf("%d", uid)
	}
	return u.Username
}

func lookupGroup(gid int) string {
	if gid == -1 {
		return "[unknown]"
	}
	g, err := user.LookupGroupId(strconv.Itoa(gid))
	if err != nil {
		return fmt.Sprintf("%d", gid)
	}
	return g.Name
}

func uidToUser(uid int) string {
	uname, ok := userMap[uid]
	if ok {
		return uname
	}
	uname = lookupUser(uid)
	userMap[uid] = uname
	return uname
}

func gidToGroup(gid int) string {
	gname, ok := groupMap[gid]
	if ok {
		return gname
	}
	gname = lookupGroup(gid)
	groupMap[gid] = gname
	return gname
}
