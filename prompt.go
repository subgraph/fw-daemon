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
	pp := p.nextPacket()
	if pp == nil {
		return false
	}
	p.lock.Unlock()
	defer p.lock.Lock()
	p.processPacket(pp)
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

func (p *prompter) processPacket(pp *pendingPkt) {
	var scope int32
	var rule string

	addr := pp.hostname
	if addr == "" {
		addr = pp.pkt.Dst.String()
	}

	call := p.dbusObj.Call("com.subgraph.FirewallPrompt.RequestPrompt", 0,
		pp.policy.application,
		pp.policy.icon,
		pp.policy.path,
		addr,
		int32(pp.pkt.DstPort),
		pp.pkt.Dst.String(),
		uidToUser(pp.pinfo.Uid),
		int32(pp.pinfo.Pid))
	err := call.Store(&scope, &rule)
	if err != nil {
		log.Warning("Error sending dbus RequestPrompt message: %v", err)
		pp.policy.removePending(pp)
		pp.pkt.Mark = 1
		pp.pkt.Accept()
		//pp.pkt.Drop()
		return
	}
	log.Debug("Received prompt response: %s [%s]", printScope(scope), rule)

	r, err := parseRule(rule)
	if err != nil {
		log.Warning("Error parsing rule string returned from dbus RequestPrompt: %v", err)
		pp.policy.removePending(pp)
		pp.pkt.Mark = 1
		pp.pkt.Accept()
		//pp.pkt.Drop()
		return
	}
	if scope == APPLY_SESSION {
		r.sessionOnly = true
	}
	if !pp.policy.processNewRule(r, scope) {
		p.lock.Lock()
		defer p.lock.Unlock()
		p.removePolicy(pp.policy)
	}
	if scope == APPLY_FOREVER {
		pp.policy.fw.saveRules()
	}
}

func (p *prompter) nextPacket() *pendingPkt {
	for {
		if len(p.policyQueue) == 0 {
			return nil
		}
		policy := p.policyQueue[0]
		pp := policy.nextPending()
		if pp == nil {
			p.removePolicy(policy)
		} else {
			return pp
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
