package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"
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
	log.Info("SetEnabled(%v) called", flag)
	return nil
}

func (ds *dbusServer) IsEnabled() (bool, *dbus.Error) {
	log.Info("IsEnabled() called")
	return true, nil
}

func (ds *dbusServer) prompt(p *Policy) {
	log.Info("prompting...")
	ds.prompter.prompt(p)
}
