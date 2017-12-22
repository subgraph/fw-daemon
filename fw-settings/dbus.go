package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/subgraph/fw-daemon/sgfw"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"

	"github.com/gotk3/gotk3/glib"
)

type dbusObject struct {
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
	fmt.Printf("Deleting rule: %d\n", id)
	res := ob.Call("com.subgraph.Firewall.DeleteRule", 0, id)
	if res.Err != nil {
		fmt.Printf("DBUS Delete error with %+v\n", res.Err)
	}
}

func (ob *dbusObject) updateRule(rule *sgfw.DbusRule) {
	fmt.Printf("Updating rule: %+v\n", rule)
	res := ob.Call("com.subgraph.Firewall.UpdateRule", 0, rule)
	if res.Err != nil {
		fmt.Printf("DBUS UPdate error with %+v\n", res.Err)
	}
}

func (ob *dbusObject) answerPrompt(scope uint32, rule, guid string) error {
	var dres bool
	call := ob.Call("AddRuleAsync", 0, uint32(scope), rule, "*", guid)

	err := call.Store(&dres)
	if err != nil {
		fmt.Printf("Error notifying SGFW of asynchronous rule addition: %+v\n", err)
		return err
	}

	fmt.Println("makeDecision remote result:", dres)
	return nil
}

func (ob *dbusObject) addRule(rule *sgfw.DbusRule) (bool, error) {
	var dres bool
	fmt.Printf("Adding new rule: %+v\n", rule)
	call := ob.Call("com.subgraph.Firewall.AddNewRule", 0, rule)
	err := call.Store(&dres)
	if err != nil {
		fmt.Println("Error while adding new rule:", err)
		return false, err
	}
	return dres, nil
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

func dbusSignalHandler(app *fwApp) {
	for {
		conn, err := dbus.SystemBus()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to connect to bus: ", err)
		}
		defer conn.Close()

		conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0,
			"type='signal',path='/com/subgraph/Firewall',interface='com.subgraph.Firewall',sender='com.subgraph.Firewall'")

		c := make(chan *dbus.Signal, 10)
		conn.Signal(c)
		for v := range c {
			if !strings.HasPrefix(v.Name, "com.subgraph.Firewall.") {
				continue
			}
			if len(v.Body) == 0 {
				continue
			}
			val := v.Body[0].(string)
			name := strings.ToLower(strings.Replace(v.Name, "com.subgraph.Firewall.", "", 1))
			fmt.Printf("Received Dbus update alert: %s(%v)\n", name, val)
			switch name {
			case "refresh":
				switch val {
				case "init":
					glib.IdleAdd(func () bool {
						if app.promptMode != promptModeDisabled {
							app.prompt.RemoveAll()
						}
						app.handleRefreshRules()
						app.handleRefreshConfig()
						return false
					})
				case "rules":
					glib.IdleAdd(func () bool {
						app.handleRefreshRules()
						return false
					})
				case "config":
					glib.IdleAdd(func () bool {
						app.handleRefreshConfig()
						return false
					})
				default:
					continue
				}
			default:
				continue
			}
		}
	}
}


/*
 * DBus Prompt Service
 */

const introspectPromptXML = `
<node>
  <interface name="com.subgraph.FirewallPrompt">
    <method name="RequestPromptAsync">
        <arg type="s" direction="in" name="guid" />
        <arg type="s" direction="in" name="application" />
        <arg type="s" direction="in" name="icon" />
        <arg type="s" direction="in" name="path" />
        <arg type="s" direction="in" name="address" />
        <arg type="i" direction="in" name="port" />
        <arg type="s" direction="in" name="ip" />
        <arg type="s" direction="in" name="origin" />
        <arg type="s" direction="in" name="proto" />
        <arg type="i" direction="in" name="uid" />
        <arg type="i" direction="in" name="gid" />
        <arg type="s" direction="in" name="user" />
        <arg type="s" direction="in" name="group" />
        <arg type="i" direction="in" name="pid" />
        <arg type="s" direction="in" name="sandbox" />
        <arg type="b" direction="in" name="tlsguard" />
        <arg type="s" direction="in" name="timestamp" />
        <arg type="s" direction="in" name="optstring" />
        <arg type="b" direction="in" name="expanded" />
        <arg type="b" direction="in" name="expert" />
        <arg type="i" direction="in" name="action" />
        <arg type="b" direction="out" name="result" />
    </method>
    <method name="RemovePrompt">
        <arg type="s" direction="in" name="guid" />
        <arg type="b" direction="out" name="result" />
    </method>
  </interface>` +
	introspect.IntrospectDataString +
	`</node>`

func newPromptDbusServer() (*dbusServer, error) {
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

	if err := conn.Export(introspect.Introspectable(introspectPromptXML), "/com/subgraph/FirewallPrompt", "org.freedesktop.DBus.Introspectable"); err != nil {
		return nil, err
	}

	ds.conn = conn
	ds.run = true

	return ds, nil
}

func (ds *dbusServer) RequestPromptAsync(guid, application, icon, path, address string, port int32, ip, origin, proto string, uid, gid int32, username, groupname string, pid int32, sandbox string,
	is_socks bool, timestamp string, optstring string, expanded, expert bool, action int32) (bool, *dbus.Error) {
	fmt.Printf("ASYNC request prompt: guid = %s, app = %s, icon = %s, path = %s, address = %s / ip = %s, is_socks = %v, sandbox = %v, action = %v\n", guid, application, icon, path, address, ip, is_socks, sandbox, action)
	if cbPromptAddRequest != nil {
		glib.IdleAdd(func () bool {
			cbPromptAddRequest(guid, path, icon, proto, int(pid), ip, address, int(port), int(uid), int(gid), origin, timestamp, is_socks, optstring, sandbox, int(action))
			return false
		})
	}
	return true, nil
}

func (ds *dbusServer) RemovePrompt(guid string) *dbus.Error {
	fmt.Printf("++++++++ Cancelling prompt: %s\n", guid)
	if cbPromptRemoveRequest != nil {
		glib.IdleAdd(func () bool {
			cbPromptRemoveRequest(guid)
			return false
		})
	}
	return nil
}
