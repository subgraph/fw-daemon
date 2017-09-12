package main

import (
	"errors"
	"fmt"
	"github.com/godbus/dbus"
	"github.com/gotk3/gotk3/glib"
	"github.com/subgraph/fw-daemon/sgfw"
)

type dbusObject struct {
	dbus.BusObject
}

type dbusObjectP struct {
	dbus.BusObject
}

type dbusServer struct {
	conn *dbus.Conn
	run  bool
}

func newDbusObject() (*dbusObject, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	return &dbusObject{conn.Object("com.subgraph.Firewall", "/com/subgraph/Firewall")}, nil
}

func newDbusObjectPrompt() (*dbusObjectP, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	return &dbusObjectP{conn.Object("com.subgraph.fwprompt.EventNotifier", "/com/subgraph/fwprompt/EventNotifier")}, nil
}

func (ob *dbusObject) isEnabled() (bool, error) {
	var flag bool
	if err := ob.Call("com.subgraph.Firewall.IsEnabled", 0).Store(&flag); err != nil {
		return false, err
	}
	return flag, nil
}

func (ob *dbusObject) listRules() ([]sgfw.DbusRule, error) {
	rules := []sgfw.DbusRule{}
	err := ob.Call("com.subgraph.Firewall.ListRules", 0).Store(&rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func (ob *dbusObject) deleteRule(id uint32) {
	ob.Call("com.subgraph.Firewall.DeleteRule", 0, id)
}

func (ob *dbusObject) updateRule(rule *sgfw.DbusRule) {
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

func newDbusServer() (*dbusServer, error) {
	conn, err := dbus.SystemBus()

	if err != nil {
		return nil, err
	}

	reply, err := conn.RequestName("com.subgraph.fwprompt.EventNotifier", dbus.NameFlagDoNotQueue)

	if err != nil {
		return nil, err
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, errors.New("Bus name is already owned")
	}

	ds := &dbusServer{}

	if err := conn.Export(ds, "/com/subgraph/fwprompt/EventNotifier", "com.subgraph.fwprompt.EventNotifier"); err != nil {
		return nil, err
	}

	ds.conn = conn
	ds.run = true
	return ds, nil
}

func (ds *dbusServer) Alert(data string) *dbus.Error {
	fmt.Println("Received Dbus update alert: ", data)
	glib.IdleAdd(repopulateWin)
	return nil
}

func (ob *dbusObjectP) alertRule(data string) {
	ob.Call("com.subgraph.fwprompt.EventNotifier.Alert", 0, data)
}
