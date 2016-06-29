package main

import (
	"fmt"
	"github.com/subgraph/fw-daemon/Godeps/_workspace/src/github.com/godbus/dbus"
	"os/user"
	"strconv"
	"sync"
)

const (
	APPLY_ONCE = iota
	APPLY_SESSION
	APPLY_FOREVER
)

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
	_, ok := p.policyMap[policy.path]
	if ok {
		return
	}
	p.policyMap[policy.path] = policy
	p.policyQueue = append(p.policyQueue, policy)
	p.cond.Signal()
}

func (p *prompter) promptLoop() {
	p.lock.Lock()
	for {
		for p.processNextPacket() {
		}
		p.cond.Wait()
	}
}

func (p *prompter) processNextPacket() bool {
	pc := p.nextConnection()
	if pc == nil {
		return false
	}
	p.lock.Unlock()
	defer p.lock.Lock()
	p.processConnection(pc)
	return true
}

func printScope(scope int32) string {
	switch scope {
	case APPLY_FOREVER:
		return "APPLY_FOREVER"
	case APPLY_SESSION:
		return "APPLY_SESSION"
	case APPLY_ONCE:
		return "APPLY_ONCE"
	default:
		return fmt.Sprintf("Unknown (%d)", scope)
	}
}

func (p *prompter) processConnection(pc pendingConnection) {
	var scope int32
	var rule string

	addr := pc.hostname()
	if addr == "" {
		addr = pc.dst().String()
	}
	policy := pc.policy()

	call := p.dbusObj.Call("com.subgraph.FirewallPrompt.RequestPrompt", 0,
		policy.application,
		policy.icon,
		policy.path,
		addr,
		int32(pc.dstPort()),
		pc.dst().String(),
		uidToUser(pc.procInfo().UID),
		int32(pc.procInfo().Pid))
	err := call.Store(&scope, &rule)
	if err != nil {
		log.Warning("Error sending dbus RequestPrompt message: %v", err)
		policy.removePending(pc)
		pc.drop()
		return
	}

	r, err := policy.parseRule(rule, false)
	if err != nil {
		log.Warning("Error parsing rule string returned from dbus RequestPrompt: %v", err)
		policy.removePending(pc)
		pc.drop()
		return
	}
	if scope == APPLY_SESSION {
		r.sessionOnly = true
	}
	if !policy.processNewRule(r, scope) {
		p.lock.Lock()
		defer p.lock.Unlock()
		p.removePolicy(pc.policy())
	}
	if scope == APPLY_FOREVER {
		policy.fw.saveRules()
	}
}

func (p *prompter) nextConnection() pendingConnection {
	for {
		if len(p.policyQueue) == 0 {
			return nil
		}
		policy := p.policyQueue[0]
		pc := policy.nextPending()
		if pc == nil {
			p.removePolicy(policy)
		} else {
			return pc
		}
	}
}

func (p *prompter) removePolicy(policy *Policy) {
	newQueue := make([]*Policy, 0, len(p.policyQueue)-1)
	for _, pol := range p.policyQueue {
		if pol != policy {
			newQueue = append(newQueue, pol)
		}
	}
	p.policyQueue = newQueue
	delete(p.policyMap, policy.path)
}

var userMap = make(map[int]string)

func lookupUser(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return fmt.Sprintf("%d", uid)
	}
	return u.Name
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
