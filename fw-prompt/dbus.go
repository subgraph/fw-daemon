package main

import (
	"errors"
	"github.com/godbus/dbus"
	"log"
	//	"github.com/gotk3/gotk3/glib"
)

type dbusServer struct {
	conn *dbus.Conn
	run  bool
}

type promptData struct {
	Application string
	Icon        string
	Path        string
	Address     string
	Port        int
	IP          string
	Origin      string
	Proto       string
	UID         int
	GID         int
	Username    string
	Groupname   string
	Pid         int
	Sandbox     string
	OptString   string
	Expanded    bool
	Expert      bool
	Action      int
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

func (ds *dbusServer) RequestPrompt(application, icon, path, address string, port int32, ip, origin, proto string, uid, gid int32, username, groupname string, pid int32, sandbox string,
	is_socks bool, optstring string, expanded, expert bool, action int32) (int32, string, *dbus.Error) {
	log.Printf("request prompt: app = %s, icon = %s, path = %s, address = %s, is_socks = %v, action = %v\n", application, icon, path, address, is_socks, action)
	decision := addRequest(nil, path, proto, int(pid), ip, address, int(port), int(uid), int(gid), origin, is_socks, optstring, sandbox)
	log.Print("Waiting on decision...")
	decision.Cond.L.Lock()
	for !decision.Ready {
		decision.Cond.Wait()
	}
	log.Print("Decision returned: ", decision.Rule)
	decision.Cond.L.Unlock()
	//	glib.IdleAdd(func, data)
	return int32(decision.Scope), decision.Rule, nil
}
