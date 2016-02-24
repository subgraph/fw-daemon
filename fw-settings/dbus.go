package main

import (
	"github.com/subgraph/fw-daemon/Godeps/_workspace/src/github.com/godbus/dbus"
)

type dbusObject struct {
	dbus.BusObject
}

type dbusRule struct {
	Id     uint32
	App    string
	Path   string
	Verb   uint32
	Target string
}

func newDbusObject() (*dbusObject, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	return &dbusObject{conn.Object("com.subgraph.Firewall", "/com/subgraph/Firewall")}, nil
}

func (ob *dbusObject) isEnabled() (bool, error) {
	var flag bool
	if err := ob.Call("com.subgraph.Firewall.IsEnabled", 0).Store(&flag); err != nil {
		return false, err
	}
	return flag, nil
}

func (ob *dbusObject) listRules() ([]dbusRule, error) {
	rules := []dbusRule{}
	if err := ob.Call("com.subgraph.Firewall.ListRules", 0).Store(&rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func (ob *dbusObject) deleteRule(id uint32) {
	ob.Call("com.subgraph.Firewall.DeleteRule", 0, id)
}

func (ob *dbusObject) updateRule(rule *dbusRule) {
	ob.Call("com.subgraph.Firewall.UpdateRule", 0, rule)
}

func (ob *dbusObject) getConfig() (map[string]interface{}, error) {
	res := make(map[string]dbus.Variant)
	if err := ob.Call("com.subgraph.Firewall.GetConfig", 0).Store(&res); err != nil {
		return nil, err
	}
	config := make(map[string]interface{})
	for k, v := range res {
		config[k] = v.Value()
	}
	return config, nil
}

func (ob *dbusObject) setConfig(key string, val interface{}) {
	ob.Call("com.subgraph.Firewall.SetConfig", 0, key, dbus.MakeVariant(val))
}
