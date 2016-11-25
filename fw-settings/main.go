package main

import (
	"os"

	"fmt"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

func failDialog(parent *gtk.Window, format string, args ...interface{}) {
	d := gtk.MessageDialogNew(parent, 0, gtk.MESSAGE_ERROR, gtk.BUTTONS_CLOSE,
		format, args...)
	d.Run()
	os.Exit(1)
}

func activate(app *gtk.Application) {
	win := app.GetActiveWindow()
	if win != nil {
		win.Present()
		return
	}

	var swRulesPermanent *gtk.ScrolledWindow
	var swRulesSession *gtk.ScrolledWindow
	var swRulesSystem *gtk.ScrolledWindow

	b := newBuilder("Dialog")
	b.getItems(
		"window", &win,
		"swRulesPermanent", &swRulesPermanent,
		"swRulesSession", &swRulesSession,
		"swRulesSystem", &swRulesSystem,
	)
	//win.SetIconName("security-high-symbolic")
	win.SetIconName("security-medium")

	boxPermanent, _ := gtk.ListBoxNew()
	swRulesPermanent.Add(boxPermanent)

	boxSession, _ := gtk.ListBoxNew()
	swRulesSession.Add(boxSession)

	boxSystem, _ := gtk.ListBoxNew()
	swRulesSystem.Add(boxSystem)

	dbus, err := newDbusObject()
	if err != nil {
		failDialog(win, "Failed to connect to dbus system bus: %v", err)
	}

	rlPermanent := NewRuleList(dbus, win, boxPermanent)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlPermanent.loadRules(RULE_MODE_PERMANENT)

	rlSession := NewRuleList(dbus, win, boxSession)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlSession.loadRules(RULE_MODE_SESSION)

	rlSystem := NewRuleList(dbus, win, boxSystem)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlSystem.loadRules(RULE_MODE_SYSTEM)

	loadConfig(win, b, dbus)
	app.AddWindow(win)
	win.ShowAll()
}

func main() {
	app, err := gtk.ApplicationNew("com.subgraph.Firewall.settings", glib.APPLICATION_FLAGS_NONE)
	if err != nil {
		panic(fmt.Sprintf("gtk.ApplicationNew() failed: %v", err))
	}
	app.Connect("activate", activate)
	app.Run(os.Args)
}
