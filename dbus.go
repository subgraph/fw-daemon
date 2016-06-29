package main

import (
	"errors"
	"path"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"
	"github.com/op/go-logging"
)

const introspectXml = `
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

type dbusServer struct {
	fw       *Firewall
	conn     *dbus.Conn
	prompter *prompter
}

type DbusRule struct {
	Id     uint32
	App    string
	Path   string
	Verb   uint32
	Target string
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
	if err := conn.Export(introspect.Introspectable(introspectXml), objectPath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return nil, err
	}

	ds.conn = conn
	ds.prompter = newPrompter(conn)
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
	return DbusRule{
		Id:     uint32(r.id),
		App:    path.Base(r.policy.path),
		Path:   r.policy.path,
		Verb:   uint32(r.rtype),
		Target: r.AddrString(false),
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
	r := ds.fw.rulesById[uint(id)]
	ds.fw.lock.Unlock()
	if r != nil {
		r.policy.removeRule(r)
	}
	if !r.sessionOnly {
		ds.fw.saveRules()
	}
	return nil
}

func (ds *dbusServer) UpdateRule(rule DbusRule) *dbus.Error {
	log.Debugf("UpdateRule %v", rule)
	ds.fw.lock.Lock()
	r := ds.fw.rulesById[uint(rule.Id)]
	ds.fw.lock.Unlock()
	if r != nil {
		tmp := new(Rule)
		tmp.addr = noAddress
		if !tmp.parseTarget(rule.Target) {
			log.Warningf("Unable to parse target: %s", rule.Target)
			return nil
		}
		r.policy.lock.Lock()
		if rule.Verb == RULE_ALLOW || rule.Verb == RULE_DENY {
			r.rtype = int(rule.Verb)
		}
		r.hostname = tmp.hostname
		r.addr = tmp.addr
		r.port = tmp.port
		r.policy.lock.Unlock()
		if !r.sessionOnly {
			ds.fw.saveRules()
		}
	}
	return nil
}

func (ds *dbusServer) GetConfig() (map[string]dbus.Variant, *dbus.Error) {
	conf := make(map[string]dbus.Variant)
	conf["loglevel"] = dbus.MakeVariant(int32(ds.fw.logBackend.GetLevel("sgfw")))
	conf["logredact"] = dbus.MakeVariant(logRedact)
	return conf, nil
}

func (ds *dbusServer) SetConfig(key string, val dbus.Variant) *dbus.Error {
	switch key {
	case "loglevel":
		l := val.Value().(int32)
		lvl := logging.Level(l)
		ds.fw.logBackend.SetLevel(lvl, "sgfw")
	case "logredact":
		flag := val.Value().(bool)
		logRedact = flag
	}
	return nil
}

func (ds *dbusServer) prompt(p *Policy) {
	log.Info("prompting...")
	ds.prompter.prompt(p)
}
