package sgfw

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"sync"

	"github.com/godbus/dbus"
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
		pc.src().String(),
		pc.proto(),
		int32(pc.procInfo().UID),
		int32(pc.procInfo().GID),
		uidToUser(pc.procInfo().UID),
		gidToGroup(pc.procInfo().GID),
		int32(pc.procInfo().Pid),
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

	if pc.src() != nil {
		if !strings.HasSuffix(rule, "SYSTEM") && !strings.HasSuffix(rule, "||") {
			rule += "|"
		}
		rule += "||" + pc.src().String()
	}

	r, err := policy.parseRule(rule, false)
	if err != nil {
		log.Warningf("Error parsing rule string returned from dbus RequestPrompt: %v", err)
		policy.removePending(pc)
		pc.drop()
		return
	}
	fscope := FilterScope(scope)
	if fscope == APPLY_SESSION {
		r.mode = RULE_MODE_SESSION
	}
	if !policy.processNewRule(r, fscope) {
		p.lock.Lock()
		defer p.lock.Unlock()
		p.removePolicy(pc.policy())
	}
	if fscope == APPLY_FOREVER {
		policy.fw.saveRules()
	}
	dbusp.alertRule("sgfw prompt added new rule")
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
