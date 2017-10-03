package main

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus"
)


const busName = "com.subgraph.FirewallTest"
const objectPath = "/com/subgraph/FirewallTest"
const interfaceName = "com.subgraph.FirewallTest"

type dbusObjectP struct {
	dbus.BusObject
}

func newDbusObjectAdd() (*dbusObjectP, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	return &dbusObjectP{conn.Object("com.subgraph.Firewall", "/com/subgraph/Firewall")}, nil
}

type dbusServer struct {
	conn     *dbus.Conn
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

	ds.conn = conn
	return ds, nil
}

func (ds *dbusServer) SGFWTestAlert(accepted int32, guid string, other string) (bool, *dbus.Error) {
	fmt.Printf("<- SGFWTestAlert(accepted = %v, guid = %s, other=[%s])\n", accepted, guid, other)

	return true, nil
}

func CallAddTestVPC(d *dbusObjectP, proto string, srcip string, sport uint16, dstip string, dport uint16, hostname string) bool {
	var dres bool

	fmt.Printf("CallAddTestVPC(proto=%s, srcip=%s, sport=%u, dstip=%s, dport=%u, hostname=%s)\n",
		proto, srcip, sport, dstip, dport, hostname)

	call := d.Call("AddTestVPC", 0,
		proto, srcip, sport, dstip, dport, hostname)

	err := call.Store(&dres)
	if err != nil {
		fmt.Println("Error sending DBus AddTestVPC() request:", err)
		return false
	}

	return true
}
