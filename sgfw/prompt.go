package sgfw

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus"
	"github.com/subgraph/fw-daemon/proc-coroner"
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
	_, ok := p.policyMap[policy.sandbox+"|"+policy.path]
	if ok {
		p.cond.Signal()
		return
	}
	p.policyMap[policy.sandbox+"|"+policy.path] = policy
	log.Debugf("Saving policy key:" + policy.sandbox + "|" + policy.path)
	p.policyQueue = append(p.policyQueue, policy)
	p.cond.Signal()
}

func (p *prompter) promptLoop() {
	//	p.lock.Lock()
	for {
		// fmt.Println("XXX: promptLoop() outer")
		p.lock.Lock()
		for p.processNextPacket() {
			// fmt.Println("XXX: promptLoop() inner")
		}
		p.lock.Unlock()
		// fmt.Println("promptLoop() wait")
		//		p.cond.Wait()
	}
}

func (p *prompter) processNextPacket() bool {
	var pc pendingConnection = nil

	/*	if 1 == 2 {
		//	if !DoMultiPrompt {
		pc, _ = p.nextConnection()
		if pc == nil {
			return false
		}
		p.lock.Unlock()
		defer p.lock.Lock()
		p.processConnection(pc)
		return true
	} */

	empty := true
	for {
		pc, empty = p.nextConnection()
		fmt.Println("XXX: processNextPacket() loop; empty = ", empty, " / pc = ", pc)
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
	if pc.getPrompting() {
		log.Debugf("Skipping over already prompted connection")
	}

	pc.setPrompting(true)
	go p.processConnection(pc)
	return true
}

type PC2FDMapping struct {
	guid     string
	inode    uint64
	fd       int
	fdpath   string
	prompter *prompter
}

var PC2FDMap = map[string]PC2FDMapping{}
var PC2FDMapLock = &sync.Mutex{}
var PC2FDMapRunning = false

func monitorPromptFDs(pc pendingConnection) {
	guid := pc.getGUID()
	pid := pc.procInfo().Pid
	inode := pc.procInfo().Inode
	fd := pc.procInfo().FD
	prompter := pc.getPrompter()

	fmt.Printf("ADD TO MONITOR: %v | %v / %v / %v\n", pc.policy().application, guid, pid, fd)

	if pid == -1 || fd == -1 || prompter == nil {
		log.Warning("Unexpected error condition occurred while adding socket fd to monitor")
		return
	}

	PC2FDMapLock.Lock()
	defer PC2FDMapLock.Unlock()

	fdpath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	PC2FDMap[guid] = PC2FDMapping{guid: guid, inode: inode, fd: fd, fdpath: fdpath, prompter: prompter}
	return
}

func monitorPromptFDLoop() {
	fmt.Println("++++++++++= monitorPromptFDLoop()")

	for true {
		delete_guids := []string{}
		PC2FDMapLock.Lock()
		fmt.Println("++++ nentries = ", len(PC2FDMap))

		for guid, fdmon := range PC2FDMap {
			fmt.Println("ENTRY:", fdmon)

			lsb, err := os.Stat(fdmon.fdpath)
			if err != nil {
				log.Warningf("Error looking up socket \"%s\": %v\n", fdmon.fdpath, err)
				delete_guids = append(delete_guids, guid)
				continue
			}

			sb, ok := lsb.Sys().(*syscall.Stat_t)
			if !ok {
				log.Warning("Not a syscall.Stat_t")
				delete_guids = append(delete_guids, guid)
				continue
			}

			inode := sb.Ino
			fmt.Println("+++ INODE = ", inode)

			if inode != fdmon.inode {
				fmt.Printf("inode mismatch: %v vs %v\n", inode, fdmon.inode)
				delete_guids = append(delete_guids, guid)
			}

		}

		fmt.Println("guids to delete: ", delete_guids)
		saved_mappings := []PC2FDMapping{}
		for _, guid := range delete_guids {
			saved_mappings = append(saved_mappings, PC2FDMap[guid])
			delete(PC2FDMap, guid)
		}

		PC2FDMapLock.Unlock()

		for _, mapping := range saved_mappings {
			call := mapping.prompter.dbusObj.Call("com.subgraph.FirewallPrompt.RemovePrompt", 0, mapping.guid)
			fmt.Println("DISPOSING CALL = ", call)
			prompter := mapping.prompter

			prompter.lock.Lock()

			for _, policy := range prompter.policyQueue {
				policy.lock.Lock()
				pcind := 0

				for pcind < len(policy.pendingQueue) {

					if policy.pendingQueue[pcind].getGUID() == mapping.guid {
						fmt.Println("-------------- found guid to remove")
						policy.pendingQueue = append(policy.pendingQueue[:pcind], policy.pendingQueue[pcind+1:]...)
					} else {
						pcind++
					}

				}

				policy.lock.Unlock()
			}

			prompter.lock.Unlock()
		}

		fmt.Println("++++++++++= monitorPromptFDLoop WAIT")
		time.Sleep(5 * time.Second)
	}

}

func (p *prompter) processConnection(pc pendingConnection) {
	var scope int32
	var dres bool
	var rule string

	if !PC2FDMapRunning {
		PC2FDMapLock.Lock()

		if !PC2FDMapRunning {
			PC2FDMapRunning = true
			PC2FDMapLock.Unlock()
			go monitorPromptFDLoop()
		}

	}

	if pc.getPrompter() == nil {
		pc.setPrompter(p)
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
		dststr = addr + " (via proxy resolver)"
	}

	//	callChan := make(chan *dbus.Call, 10)
	//	saveChannel(callChan, true, false)
	//	fmt.Println("# outstanding prompt chans = ", len(outstandingPromptChans))

	//	fmt.Println("ABOUT TO CALL ASYNC PROMPT")
	monitorPromptFDs(pc)
	call := p.dbusObj.Call("com.subgraph.FirewallPrompt.RequestPromptAsync", 0,
		pc.getGUID(),
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

	err := call.Store(&dres)
	if err != nil {
		log.Warningf("Error sending dbus async RequestPrompt message: %v", err)
		policy.removePending(pc)
		pc.drop()
		return
	}

	if !dres {
		fmt.Println("Unexpected: fw-prompt async RequestPrompt message returned:", dres)
	}

	return

	/*	p.dbusObj.Go("com.subgraph.FirewallPrompt.RequestPrompt", 0, callChan,
			pc.getGUID(),
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

		select {
		case call := <-callChan:

			if call.Err != nil {
				fmt.Println("Error reading DBus channel (accepting packet): ", call.Err)
				policy.removePending(pc)
				pc.accept()
				saveChannel(callChan, false, true)
				time.Sleep(1 * time.Second)
				return
			}

			if len(call.Body) != 2 {
				log.Warning("SGFW got back response in unrecognized format, len = ", len(call.Body))
				saveChannel(callChan, false, true)

				if (len(call.Body) == 3) && (call.Body[2] == 666) {
					fmt.Printf("+++++++++ AWESOME: %v | %v | %v\n", call.Body[0], call.Body[1], call.Body[2])
					scope = call.Body[0].(int32)
					rule = call.Body[1].(string)
				}

				return
			}

			fmt.Printf("DBUS GOT BACK: %v, %v\n", call.Body[0], call.Body[1])
			scope = call.Body[0].(int32)
			rule = call.Body[1].(string)
		}

		saveChannel(callChan, false, true)

		// Try alerting every other channel
		promptData := make([]interface{}, 3)
		promptData[0] = scope
		promptData[1] = rule
		promptData[2] = 666
		promptChanLock.Lock()
		fmt.Println("# channels to alert: ", len(outstandingPromptChans))

		for chidx, _ := range outstandingPromptChans {
			alertChannel(chidx, scope, rule)
			//		ch <- &dbus.Call{Body: promptData}
		}

		promptChanLock.Unlock() */

	/*	err := call.Store(&scope, &rule)
		if err != nil {
			log.Warningf("Error sending dbus RequestPrompt message: %v", err)
			policy.removePending(pc)
			pc.drop()
			return
		} */

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
	pind := 0

	if len(p.policyQueue) == 0 {
		return nil, true
	}
	fmt.Println("policy queue len = ", len(p.policyQueue))

	for pind < len(p.policyQueue) {
		fmt.Printf("pind = %v of %v\n", pind, len(p.policyQueue))
		policy := p.policyQueue[pind]
		pc, qempty := policy.nextPending()

		if pc == nil && qempty {
			p.removePolicy(policy)
			continue
		} else {
			pind++
			//			if pc == nil && !qempty {

			if len(policy.rulesPending) > 0 {
				fmt.Println("policy rules pending = ", len(policy.rulesPending))

				prule := policy.rulesPending[0]
				policy.rulesPending = append(policy.rulesPending[:0], policy.rulesPending[1:]...)

				toks := strings.Split(prule.rule, "|")
				sandbox := ""

				if len(toks) > 2 {
					sandbox = toks[2]
				}

				tempRule := fmt.Sprintf("%s|%s", toks[0], toks[1])

				/*					if pc.src() != nil && !pc.src().Equal(net.ParseIP("127.0.0.1")) && sandbox != "" {
									tempRule += "||-1:-1|" + sandbox + "|" + pc.src().String()
								} else {*/
				tempRule += "||-1:-1|" + sandbox + "|"
				//					}

				r, err := policy.parseRule(tempRule, false)
				if err != nil {
					log.Warningf("Error parsing rule string returned from dbus RequestPrompt: %v", err)
					//						policy.removePending(pc)
					//						pc.drop()
					//						return
				} else {
					fscope := FilterScope(prule.scope)
					if fscope == APPLY_SESSION {
						r.mode = RULE_MODE_SESSION
					} else if fscope == APPLY_PROCESS {
						r.mode = RULE_MODE_PROCESS
						//							r.pid = pc.procInfo().Pid
						//							pcoroner.MonitorProcess(r.pid)
					}
					if !policy.processNewRule(r, fscope) {
						//							p.lock.Lock()
						//							defer p.lock.Unlock()
						//							p.removePolicy(pc.policy())
					}
					if fscope == APPLY_FOREVER {
						r.mode = RULE_MODE_PERMANENT
						policy.fw.saveRules()
					}
					log.Warningf("Prompt returning rule: %v", tempRule)
					dbusp.alertRule("sgfw prompt added new rule")
				}

			}

			if pc == nil && !qempty {
				//				log.Errorf("FIX ME: I NEED TO SLEEP ON A WAKEABLE CONDITION PROPERLY!!")
				time.Sleep(time.Millisecond * 300)
				continue
			}

			if pc != nil && pc.getPrompting() {
				fmt.Println("SKIPPING PROMPTED")
				continue
			}

			return pc, qempty
		}
	}

	return nil, true
}

func (p *prompter) removePolicy(policy *Policy) {
	var newQueue []*Policy = nil

	//	if DoMultiPrompt {
	if len(p.policyQueue) == 0 {
		log.Debugf("Skipping over zero length policy queue")
		newQueue = make([]*Policy, 0, 0)
	}
	//	}

	//	if !DoMultiPrompt || newQueue == nil {
	if newQueue == nil {
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
var userMapLock = &sync.Mutex{}
var groupMapLock = &sync.Mutex{}

func lookupUser(uid int) string {
	if uid == -1 {
		return "[unknown]"
	}

	userMapLock.Lock()
	defer userMapLock.Unlock()

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

	groupMapLock.Lock()
	defer groupMapLock.Unlock()

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
