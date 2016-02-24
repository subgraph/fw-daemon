package main

import (
	"os"

	"fmt"
	"github.com/subgraph/fw-daemon/Godeps/_workspace/src/github.com/gotk3/gotk3/glib"
	"github.com/subgraph/fw-daemon/Godeps/_workspace/src/github.com/gotk3/gotk3/gtk"
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

	var scrolled *gtk.ScrolledWindow

	b := newBuilder("Dialog")
	b.getItems(
		"window", &win,
		"scrolledwindow", &scrolled,
	)
	win.SetIconName("security-high-symbolic")

	box, _ := gtk.ListBoxNew()
	scrolled.Add(box)

	dbus, err := newDbusObject()
	if err != nil {
		failDialog(win, "Failed to connect to dbus system bus: %v", err)
	}

	rl := NewRuleList(dbus, win, box)

	if _, err := dbus.isEnabled(); err != nil {
		failDialog(win, "Unable is connect to firewall daemon.  Is it running?")
	}
	rl.loadRules()
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
