package sgfw

import (
	"errors"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"
	"github.com/op/go-logging"
	"github.com/subgraph/fw-daemon/proc-coroner"
)

const introspectXML = `
<node>
  <interface name="com.subgraph.Firewall">
    <method name="SetEnabled">
      <arg name="enabled" direction="in" type="b" />
    </method>

    <method name="IsEnabled">
      <arg name="enabled" direction="out" type="b" />
    </method>

    <method name="ListRules">
      <arg name="rules" direction="out" type="a(usssusssqsqbsuuss)" />
    </method>

    <method name="DeleteRule">
      <arg name="id" direction="in" type="u" />
    </method>

    <method name="UpdateRule">
      <arg name="rule" direction="in" type="(ussus)" />
    </method>

    <method name="GetConfig">
      <arg name="config" direction="out" type="a{sv}" />
    </method>

    <method name="SetConfig">
      <arg name="key" direction="in" type="s" />
      <arg name="val" direction="in" type="v" />
    </method>

    <method name="GetPendingRequests">
      <arg name="policy" direction="in" type="s" />
      <arg name="result" direction="out" type="b" />
    </method>

    <method name="AddRuleAsync">
      <arg name="scope" direction="in" type="u" />
      <arg name="rule" direction="in" type="s" />
      <arg name="policy" direction="in" type="s" />
      <arg name="guid" direction="in" type="s" />
      <arg name="result" direction="out" type="b" />
    </method>

    <method name="AddNewRule">
      <arg name="rule" direction="in" type="usssusssqsqsuuss" />
      <arg name="result" direction="out" type="b" />
    </method>

    <signal name="Refresh">
      <arg name="refresh_event" type="s" />
    </signal>
  </interface>` +
	introspect.IntrospectDataString +
	`</node>`

const busName = "com.subgraph.Firewall"
const objectPath = "/com/subgraph/Firewall"
const interfaceName = "com.subgraph.Firewall"

type dbusObjectP struct {
	dbus.BusObject
}

func newDbusRedactedLogger() (*dbusObjectP, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	return &dbusObjectP{conn.Object("com.subgraph.sublogmon", "/com/subgraph/sublogmon")}, nil
}

type dbusServer struct {
	fw       *Firewall
	conn     *dbus.Conn
	prompter *prompter
}

func DbusProcDeathCB(pid int, param interface{}) {
	ds := param.(*dbusServer)
	ds.fw.lock.Lock()
	defer ds.fw.lock.Unlock()
	done, updated := false, false
	for !done {
		done = true
		for _, p := range ds.fw.policies {
			for r := 0; r < len(p.rules); r++ {
				if p.rules[r].pid == pid && p.rules[r].mode == RULE_MODE_PROCESS {
					p.rules = append(p.rules[:r], p.rules[r+1:]...)
					done = false
					updated = true
					log.Notice("Removed per-process firewall rule for PID: ", pid)
					break
				}
			}
		}
	}

	if updated {
		ds.fw.dbus.emitRefresh("removed")
	}
}

func newDbusServer() (*dbusServer, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	reply, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return nil, err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, errors.New("Bus name is already owned")
	}
	ds := &dbusServer{}

	if err := conn.Export(ds, objectPath, interfaceName); err != nil {
		return nil, err
	}
	if err := conn.Export(introspect.Introspectable(introspectXML), objectPath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return nil, err
	}

	ds.conn = conn
	ds.prompter = newPrompter(ds)
	pcoroner.AddCallback(DbusProcDeathCB, ds)
	return ds, nil
}

func (ds *dbusServer) SetEnabled(flag bool) *dbus.Error {
	log.Debugf("SetEnabled(%v) called", flag)
	ds.fw.setEnabled(flag)
	return nil
}

func (ds *dbusServer) IsEnabled() (bool, *dbus.Error) {
	log.Debug("IsEnabled() called")
	return ds.fw.isEnabled(), nil
}

func createDbusRule(r *Rule) DbusRule {
	netstr := ""
	if r.network != nil {
		netstr = r.network.String()
	}
	ostr := ""
	if r.saddr != nil {
		ostr = r.saddr.String()
	}
	pstr := ""

	if r.uname != "" {
		pstr = r.uname
	} else if r.uid >= 0 {
		pstr = strconv.Itoa(r.uid)
	}
	if r.gname != "" {
		pstr += ":" + r.gname
	} else if r.gid >= 0 {
		pstr += ":" + strconv.Itoa(r.gid)
	}

	return DbusRule {
		ID:       uint32(r.id),
		Net:      netstr,
		Origin:   ostr,
		Proto:    r.proto,
		Pid:      uint32(r.pid),
		Privs:    pstr,
		App:      path.Base(r.policy.path),
		Path:     r.policy.path,
		Verb:     uint16(r.rtype),
		Target:   r.AddrString(false),
		Mode:     uint16(r.mode),
		IsSocks:  false,//r.is_socks,
		Sandbox:  r.policy.sandbox,
		Realm:    r.policy.sandbox,
		UID:      int32(r.uid),
		GID:      int32(r.gid),
		Username: r.uname,
		Group:    r.gname,
	}
}

func (ds *dbusServer) ListRules() ([]DbusRule, *dbus.Error) {
	ds.fw.lock.Lock()
	defer ds.fw.lock.Unlock()
	var result []DbusRule
	for _, p := range ds.fw.policies {
		for _, r := range p.rules {
			result = append(result, createDbusRule(r))
		}
	}
	return result, nil
}

func (ds *dbusServer) DeleteRule(id uint32) *dbus.Error {
	ds.fw.lock.Lock()
	r := ds.fw.rulesByID[uint(id)]
	ds.fw.lock.Unlock()
	if r.mode == RULE_MODE_SYSTEM {
		log.Warningf("Cannot delete system rule: %s", r.String())
		return nil
	}
	if r != nil {
		r.policy.removeRule(r)
	}
	if r.mode != RULE_MODE_SESSION && r.mode != RULE_MODE_PROCESS {
		ds.fw.saveRules()
	}
	return nil
}

func (ds *dbusServer) GetPendingRequests(policy string) (bool, *dbus.Error) {
	succeeded := true

	log.Debug("+++ GetPendingRequests()")
	ds.fw.lock.Lock()
	defer ds.fw.lock.Unlock()

	for pname := range ds.fw.policyMap {
		policy := ds.fw.policyMap[pname]
		pqueue := policy.pendingQueue

		for _, pc := range pqueue {
			var dres bool
			addr := pc.hostname()
			if addr == "" {
				addr = pc.dst().String()
			}

			dststr := ""

			if pc.dst() != nil {
				dststr = pc.dst().String()
			} else {
				dststr = addr + " (via proxy resolver)"
			}

			call := ds.prompter.dbusObj.Call("com.subgraph.FirewallPrompt.RequestPromptAsync", 0,
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
				uidToUser(pc.sandbox(),pc.procInfo().UID),
				gidToGroup(pc.sandbox(),pc.procInfo().GID),
				int32(pc.procInfo().Pid),
				pc.sandbox(),
				pc.socks(),
				pc.getTimestamp(),
				pc.getOptString(),
				FirewallConfig.PromptExpanded,
				FirewallConfig.PromptExpert,
				int32(FirewallConfig.DefaultActionID))

			err := call.Store(&dres)
			if err != nil {
				log.Warningf("Error sending DBus async pending RequestPrompt message: %v", err)
				succeeded = false
			}

		}

	}

	return succeeded, nil
}

func (ds *dbusServer) AddRuleAsync(scope uint32, rule, policy, guid string) (bool, *dbus.Error) {
	log.Debug("AddRuleAsync %v, %v / %v / %v\n", scope, rule, policy, guid)
	ds.fw.lock.Lock()
	defer ds.fw.lock.Unlock()

	prule := PendingRule{rule: rule, scope: int(scope), policy: policy, guid: guid}

	for pname := range ds.fw.policyMap {
		log.Debugf("+++ Adding prule to policy: %s >>> %+b", pname, ds.fw.policyMap[pname].promptInProgress)
		ds.fw.policyMap[pname].rulesPending = append(ds.fw.policyMap[pname].rulesPending, prule)
	}

	return true, nil
}

func (ds *dbusServer) RunDebugCmd(cmd string, params string) (string, *dbus.Error) {
	cmd = strings.ToLower(cmd)
	result := "Unrecognized debug command: " + cmd

	if cmd == "monitorfds" {
		result = dumpMonitoredFDs()
	} else if cmd == "listpending" {
		result = dumpPendingQueues()
	}

	return result, nil
}

func (ds *dbusServer) AddTestVPC(proto string, srcip string, sport uint16, dstip string, dport uint16, hostname string) (bool, *dbus.Error) {
	log.Warningf("AddTestVPC(proto=%s, srcip=%s, sport=%v, dstip=%s, dport=%v, hostname=%s)\n",
		proto, srcip, sport, dstip, dport, hostname)

	sip := net.ParseIP(srcip)
	if sip == nil {
		log.Error("Test virtual rule supplied bad source IP: ", srcip)
		return false, nil
	}

	dip := net.ParseIP(srcip)
	if dip == nil {
		log.Error("Test virtual rule supplied bad dst IP: ", dstip)
		return false, nil
	}

	now := time.Now()
	optstring := "[virtual connection (TEST)]"
	pinfo := getEmptyPInfo()

	exepath := "/bin/bla"
	pid := 666
	sandbox := ""

	policy := ds.fw.PolicyForPathAndSandbox(GetRealRoot(exepath, pid), sandbox)
	vpc := &virtualPkt{_proto: proto, srcip: sip, sport: sport, dstip: dip, dport: dport, name: hostname, timestamp: now, optstring: optstring, pol: policy, pinfo: pinfo}
	policy.processPromptResult(vpc)

	log.Warning("NEW VPC: ", vpc)
	return true, nil
}

func (ds *dbusServer) AddNewRule(rule DbusRule) (bool, *dbus.Error) {
	log.Debugf("AddNewRule %+v\n", rule)
	var pn *Policy
	if rule.Sandbox != "" {
		pn = ds.fw.PolicyForPathAndSandbox(rule.Path, rule.Sandbox)
	} else {
		pn = ds.fw.PolicyForPath(rule.Path)
	}
	if RuleMode(rule.Mode) == RULE_MODE_SYSTEM {
		log.Warningf("Cannot modify system rule: %+v", rule)
		return false,nil
	}
	if rule.ID != 0 {
		if RuleMode(rule.Mode) != RULE_MODE_PROCESS && RuleMode(rule.Mode) != RULE_MODE_SESSION {
			log.Warningf("Saving a session/process rule as new without an ID?")
			return false,nil
		}
		ds.fw.lock.Lock()
		rr := ds.fw.rulesByID[uint(rule.ID)]
		ds.fw.lock.Unlock()
		if rr == nil {
			log.Noticef("Saving a session/process rule as new without a valid ID?")
		} else {
			rr.policy.lock.Lock()
			rr.policy.removeRule(rr)
			rr.policy.lock.Unlock()
		}
		rule.ID = 0
		rule.Mode = uint16(RULE_MODE_PERMANENT)
	}
	/*
	pn.lock.Lock()
	defer pn.lock.Unlock()
	if RuleMode(rule.Mode) == RULE_MODE_PROCESS || RuleMode(rule.Mode) == RULE_MODE_SESSION {
		if rule.ID == 0 {
			log.Warningf("Saving a session/process rule as new without an ID?")
			return false,nil
		}
		ds.fw.lock.Lock()
		rr := ds.fw.rulesByID[uint(rule.ID)]
		ds.fw.lock.Unlock()
		if rr == nil {
			log.Warningf("Saving a session/process rule as new without a valid ID?")
			return false,nil
		}
		
		pn.removeRule(rr)
		rule.Mode = uint16(RULE_MODE_PERMANENT)
	}
*/
	r := new(Rule)
	r.addr = noAddress
	if !r.parseTarget(rule.Target) {
		log.Warningf("Unable to parse target: %s", rule.Target)
		return false, nil
	}
	if RuleAction(rule.Verb) == RULE_ACTION_ALLOW || RuleAction(rule.Verb) == RULE_ACTION_ALLOW_TLSONLY || RuleAction(rule.Verb) == RULE_ACTION_DENY {
		r.rtype = RuleAction(rule.Verb)
	}
	r.hostname = r.hostname
	r.addr = r.addr
	r.proto = rule.Proto
	r.port = r.port
	r.uid = int(rule.UID)
	r.gid = int(rule.GID)
	r.mode = RuleMode(rule.Mode)
	r.policy = pn

	ds.fw.addRule(r)

	pn.lock.Lock()
	pn.rules = append(pn.rules, r)
	pn.lock.Unlock()
	if r.mode != RULE_MODE_SESSION && r.mode != RULE_MODE_PROCESS {
		ds.fw.saveRules()
	}

	ds.fw.dbus.emitRefresh("rules")

	return true, nil
}

func (ds *dbusServer) UpdateRule(rule DbusRule) *dbus.Error {
	log.Debugf("UpdateRule %v", rule)
	ds.fw.lock.Lock()
	r := ds.fw.rulesByID[uint(rule.ID)]
	ds.fw.lock.Unlock()
	if r != nil {
		if r.mode == RULE_MODE_SYSTEM {
			log.Warningf("Cannot modify system rule: %s", r.String())
			return nil
		}
		tmp := new(Rule)
		tmp.addr = noAddress
		if !tmp.parseTarget(rule.Target) {
			log.Warningf("Unable to parse target: %s", rule.Target)
			return nil
		}
		r.policy.lock.Lock()
		if RuleAction(rule.Verb) == RULE_ACTION_ALLOW || RuleAction(rule.Verb) == RULE_ACTION_ALLOW_TLSONLY || RuleAction(rule.Verb) == RULE_ACTION_DENY {
			r.rtype = RuleAction(rule.Verb)
		}
		r.hostname = tmp.hostname
		r.proto = rule.Proto
		//r.pid = tmp.pid
		r.addr = tmp.addr
		r.port = tmp.port
		r.uid = int(rule.UID)
		r.gid = int(rule.GID)
		r.mode = RuleMode(rule.Mode)
		r.policy.lock.Unlock()
		if r.mode != RULE_MODE_SESSION && r.mode != RULE_MODE_PROCESS {
			ds.fw.saveRules()
		}

		ds.fw.dbus.emitRefresh("rules")
	} else {
		log.Warning("Failed to update rule, rule id `%d` missing.", rule.ID)
	}
	return nil
}

func (ds *dbusServer) GetConfig() (map[string]dbus.Variant, *dbus.Error) {
	conf := make(map[string]dbus.Variant)
	conf["log_level"] = dbus.MakeVariant(int32(ds.fw.logBackend.GetLevel("sgfw")))
	conf["log_redact"] = dbus.MakeVariant(FirewallConfig.LogRedact)
	conf["prompt_expanded"] = dbus.MakeVariant(FirewallConfig.PromptExpanded)
	conf["prompt_expert"] = dbus.MakeVariant(FirewallConfig.PromptExpert)
	conf["default_action"] = dbus.MakeVariant(uint16(FirewallConfig.DefaultActionID))
	return conf, nil
}

func (ds *dbusServer) SetConfig(key string, val dbus.Variant) *dbus.Error {
	switch key {
	case "log_level":
		l := val.Value().(int32)
		lvl := logging.Level(l)
		ds.fw.logBackend.SetLevel(lvl, "sgfw")
		FirewallConfig.LoggingLevel = lvl
	case "log_redact":
		flag := val.Value().(bool)
		FirewallConfig.LogRedact = flag
	case "prompt_expanded":
		flag := val.Value().(bool)
		FirewallConfig.PromptExpanded = flag
	case "prompt_expert":
		flag := val.Value().(bool)
		FirewallConfig.PromptExpert = flag
	case "default_action":
		l := val.Value().(uint16)
		FirewallConfig.DefaultActionID = FilterScope(l)
	}
	writeConfig()
	ds.emitRefresh("config")
	return nil
}

func (ds *dbusServer) emitRefresh(data string) {
	ds.conn.Emit("/com/subgraph/Firewall", "com.subgraph.Firewall.Refresh", data)
}

func (ob *dbusObjectP) logRedacted(level string, logline string) bool {
	var dres bool
	timestamp := time.Now()
	id := "fw-daemon"

	log.Noticef("logRedacted(level=%s, timestamp=%v, logline=%s)\n", level, timestamp, logline)

	call := ob.Call("com.subgraph.sublogmon.Logger", 0,
		id, level, uint64(timestamp.UnixNano()), logline)

	err := call.Store(&dres)
	if err != nil {
		log.Warningf("Error sending redacted log message to sublogmon:", err)
		return false
	}

	return true
}
