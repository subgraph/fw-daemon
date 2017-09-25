package sgfw

import (
	"errors"
	"path"
	"strconv"

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
      <arg name="rules" direction="out" type="a(ussus)" />
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
  </interface>` +
	introspect.IntrospectDataString +
	`</node>`

const busName = "com.subgraph.Firewall"
const objectPath = "/com/subgraph/Firewall"
const interfaceName = "com.subgraph.Firewall"

type dbusObjectP struct {
	dbus.BusObject
}

func newDbusObjectPrompt() (*dbusObjectP, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	return &dbusObjectP{conn.Object("com.subgraph.fwprompt.EventNotifier", "/com/subgraph/fwprompt/EventNotifier")}, nil
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
		dbusp.alertRule("Firewall removed on process death")
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
	ds.prompter = newPrompter(conn)
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
	log.Debugf("SANDBOX SANDBOX SANDBOX: %s", r.sandbox)
	return DbusRule{
		ID:      uint32(r.id),
		Net:     netstr,
		Origin:  ostr,
		Proto:   r.proto,
		Pid:     uint32(r.pid),
		Privs:   pstr,
		App:     path.Base(r.policy.path),
		Path:    r.policy.path,
		Verb:    uint16(r.rtype),
		Target:  r.AddrString(false),
		Mode:    uint16(r.mode),
		Sandbox: r.sandbox,
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
	if r.mode != RULE_MODE_SESSION {
		ds.fw.saveRules()
	}
	return nil
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
		if RuleAction(rule.Verb) == RULE_ACTION_ALLOW || RuleAction(rule.Verb) == RULE_ACTION_DENY {
			r.rtype = RuleAction(rule.Verb)
		}
		r.hostname = tmp.hostname
		r.proto = tmp.proto
		r.pid = tmp.pid
		r.addr = tmp.addr
		r.port = tmp.port
		r.mode = RuleMode(rule.Mode)
		r.sandbox = rule.Sandbox
		r.policy.lock.Unlock()
		if r.mode != RULE_MODE_SESSION {
			ds.fw.saveRules()
		}
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
	return nil
}

func (ds *dbusServer) prompt(p *Policy) {
	log.Info("prompting...")
	ds.prompter.prompt(p)
}

func (ob *dbusObjectP) alertRule(data string) {
	ob.Call("com.subgraph.fwprompt.EventNotifier.Alert", 0, data)
}
