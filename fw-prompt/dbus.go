package main

import (
	"errors"
	"github.com/godbus/dbus"
	"log"
)

type dbusObject struct {
	dbus.BusObject
}

type dbusServer struct {
	conn *dbus.Conn
	run  bool
}

func newDbusObjectAdd() (*dbusObject, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	return &dbusObject{conn.Object("com.subgraph.Firewall", "/com/subgraph/Firewall")}, nil
}

func newDbusServer() (*dbusServer, error) {
	conn, err := dbus.SystemBus()

	if err != nil {
		return nil, err
	}

	reply, err := conn.RequestName("com.subgraph.FirewallPrompt", dbus.NameFlagDoNotQueue)

	if err != nil {
		return nil, err
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, errors.New("Bus name is already owned")
	}

	ds := &dbusServer{}

	if err := conn.Export(ds, "/com/subgraph/FirewallPrompt", "com.subgraph.FirewallPrompt"); err != nil {
		return nil, err
	}

	ds.conn = conn
	ds.run = true

	return ds, nil
}

func (ds *dbusServer) RequestPrompt(guid, application, icon, path, address string, port int32, ip, origin, proto string, uid, gid int32, username, groupname string, pid int32, sandbox string,
	is_socks bool, optstring string, expanded, expert bool, action int32) (int32, string, *dbus.Error) {
	log.Printf("request prompt: app = %s, icon = %s, path = %s, address = %s / ip = %s, is_socks = %v, action = %v\n", application, icon, path, address, ip, is_socks, action)
	decision := addRequest(nil, guid, path, icon, proto, int(pid), ip, address, int(port), int(uid), int(gid), origin, is_socks, optstring, sandbox)
	log.Print("Waiting on decision...")
	decision.Cond.L.Lock()
	for !decision.Ready {
		decision.Cond.Wait()
	}
	log.Print("Decision returned: ", decision.Rule)
	decision.Cond.L.Unlock()
	return int32(decision.Scope), decision.Rule, nil
}

func (ds *dbusServer) RequestPromptAsync(guid, application, icon, path, address string, port int32, ip, origin, proto string, uid, gid int32, username, groupname string, pid int32, sandbox string,
	is_socks bool, optstring string, expanded, expert bool, action int32) (bool, *dbus.Error) {
	log.Printf("ASYNC request prompt: guid = %s, app = %s, icon = %s, path = %s, address = %s / ip = %s, is_socks = %v, action = %v\n", guid, application, icon, path, address, ip, is_socks, action)
	addRequestAsync(nil, guid, path, icon, proto, int(pid), ip, address, int(port), int(uid), int(gid), origin, is_socks, optstring, sandbox)
	return true, nil
}

func (ds *dbusServer) RemovePrompt(guid string) *dbus.Error {
	log.Printf("++++++++ Cancelling prompt: %s\n", guid)
	removeRequest(nil, guid)
	return nil
}
