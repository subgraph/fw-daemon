package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"
)

const introspectXml = `
<node>
  <interface name="com.subgraph.Firewall">
    <method name="SetEnabled">
      <arg name="enabled" direction="in" type="b" />
    </method>
  </interface>` +
	introspect.IntrospectDataString +
	`</node>`

const busName = "com.subgraph.Firewall"
const objectPath = "/com/subgraph/Firewall"
const interfaceName = "com.subgraph.Firewall"

type dbusServer struct {
	conn     *dbus.Conn
	prompter *prompter
}

func dbusConnect() (*dbus.Conn, error) {
	// https://github.com/golang/go/issues/1435
	runtime.LockOSThread()
	syscall.Setresuid(-1, 1000, 0)

	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, err
	}
	syscall.Setresuid(0, 0, -1)
	runtime.UnlockOSThread()

	if os.Geteuid() != 0 || os.Getuid() != 0 {
		log.Warning("Not root as expected")
		os.Exit(0)
	}
	return conn, nil
}

func newDbusServer(conn *dbus.Conn) (*dbusServer, error) {
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

	ps := strings.Split(objectPath, "/")
	path := "/"
	for _, p := range ps {
		if len(path) > 1 {
			path += "/"
		}
		path += p

		if err := conn.Export(ds, dbus.ObjectPath(path), "org.freedesktop.DBus.Introspectable"); err != nil {
			return nil, err
		}
	}
	ds.conn = conn
	ds.prompter = newPrompter(conn)
	return ds, nil
}

func (ds *dbusServer) Introspect(msg dbus.Message) (string, *dbus.Error) {
	path := string(msg.Headers[dbus.FieldPath].Value().(dbus.ObjectPath))
	if path == objectPath {
		return introspectXml, nil
	}
	parts := strings.Split(objectPath, "/")
	current := "/"
	for i := 0; i < len(parts)-1; i++ {
		if len(current) > 1 {
			current += "/"
		}
		current += parts[i]
		if path == current {
			next := parts[i+1]
			return fmt.Sprintf("<node><node name=\"%s\"/></node>", next), nil
		}
	}
	return "", nil
}

func (ds *dbusServer) SetEnabled(flag bool) *dbus.Error {
	return nil
}

func (ds *dbusServer) prompt(p *Policy) {
	log.Info("prompting...")
	ds.prompter.prompt(p)
}
