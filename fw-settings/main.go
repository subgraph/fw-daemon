package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/subgraph/fw-daemon/sgfw"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

var fwswin *gtk.Window = nil
var fwsbuilder *builder = nil
var swRulesPermanent *gtk.ScrolledWindow = nil
var swRulesSession *gtk.ScrolledWindow = nil
var swRulesProcess *gtk.ScrolledWindow = nil
var swRulesSystem *gtk.ScrolledWindow = nil

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
	populateWin(app, win)
}

var repopMutex = &sync.Mutex{}

func repopulateWin() {
	fmt.Println("Refreshing firewall rule list.")
	repopMutex.Lock()
	defer repopMutex.Unlock()
	win := fwswin

	dbus, err := newDbusObject()
	if err != nil {
		failDialog(win, "Failed to connect to dbus system bus: %v", err)
	}

	child, err := swRulesPermanent.GetChild()
	if err != nil {
		failDialog(win, "Unable to clear out permanent rules list display: %v", err)
	}
	swRulesPermanent.Remove(child)

	child, err = swRulesSession.GetChild()
	if err != nil {
		failDialog(win, "Unable to clear out session rules list display: %v", err)
	}
	swRulesSession.Remove(child)

	child, err = swRulesProcess.GetChild()
	if err != nil {
		failDialog(win, "Unable to clear out process rules list display: %v", err)
	}
	swRulesProcess.Remove(child)

	child, err = swRulesSystem.GetChild()
	if err != nil {
		failDialog(win, "Unable to clear out system rules list display: %v", err)
	}
	swRulesSystem.Remove(child)

	boxPermanent, _ := gtk.ListBoxNew()
	swRulesPermanent.Add(boxPermanent)

	boxSession, _ := gtk.ListBoxNew()
	swRulesSession.Add(boxSession)

	boxProcess, _ := gtk.ListBoxNew()
	swRulesProcess.Add(boxProcess)

	boxSystem, _ := gtk.ListBoxNew()
	swRulesSystem.Add(boxSystem)

	rlPermanent := newRuleList(dbus, win, boxPermanent)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlPermanent.loadRules(sgfw.RULE_MODE_PERMANENT)

	rlSession := newRuleList(dbus, win, boxSession)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlSession.loadRules(sgfw.RULE_MODE_SESSION)

	rlProcess := newRuleList(dbus, win, boxProcess)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlProcess.loadRules(sgfw.RULE_MODE_PROCESS)

	rlSystem := newRuleList(dbus, win, boxSystem)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlSystem.loadRules(sgfw.RULE_MODE_SYSTEM)

	loadConfig(win, fwsbuilder, dbus)
	//	app.AddWindow(win)
	win.ShowAll()
}

func populateWin(app *gtk.Application, win *gtk.Window) {
	b := newBuilder("Dialog")
	fwsbuilder = b
	b.getItems(
		"window", &win,
		"swRulesPermanent", &swRulesPermanent,
		"swRulesSession", &swRulesSession,
		"swRulesProcess", &swRulesProcess,
		"swRulesSystem", &swRulesSystem,
	)
	//win.SetIconName("security-high-symbolic")
	win.SetIconName("security-medium")

	boxPermanent, _ := gtk.ListBoxNew()
	swRulesPermanent.Add(boxPermanent)

	boxSession, _ := gtk.ListBoxNew()
	swRulesSession.Add(boxSession)

	boxProcess, _ := gtk.ListBoxNew()
	swRulesProcess.Add(boxProcess)

	boxSystem, _ := gtk.ListBoxNew()
	swRulesSystem.Add(boxSystem)

	dbus, err := newDbusObject()
	if err != nil {
		failDialog(win, "Failed to connect to dbus system bus: %v", err)
	}

	rlPermanent := newRuleList(dbus, win, boxPermanent)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlPermanent.loadRules(sgfw.RULE_MODE_PERMANENT)

	rlSession := newRuleList(dbus, win, boxSession)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlSession.loadRules(sgfw.RULE_MODE_SESSION)

	rlProcess := newRuleList(dbus, win, boxProcess)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlProcess.loadRules(sgfw.RULE_MODE_PROCESS)

	rlSystem := newRuleList(dbus, win, boxSystem)
	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rlSystem.loadRules(sgfw.RULE_MODE_SYSTEM)

	loadConfig(win, b, dbus)
	app.AddWindow(win)
	fwswin = win
	win.ShowAll()
}

func main() {
	app, err := gtk.ApplicationNew("com.subgraph.Firewall.settings", glib.APPLICATION_FLAGS_NONE)
	if err != nil {
		panic(fmt.Sprintf("gtk.ApplicationNew() failed: %v", err))
	}
	app.Connect("activate", activate)

	_, err = newDbusServer()

	if err != nil {
		panic(fmt.Sprintf("Error initializing Dbus server: %v", err))
	}

	app.Run(os.Args)
}
