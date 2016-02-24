package main

import (
	"github.com/subgraph/fw-daemon/Godeps/_workspace/src/github.com/gotk3/gotk3/gtk"
	"github.com/subgraph/fw-daemon/Godeps/_workspace/src/github.com/op/go-logging"
)

var levelToId = map[int32]string{
	int32(logging.ERROR):   "error",
	int32(logging.WARNING): "warning",
	int32(logging.NOTICE):  "notice",
	int32(logging.INFO):    "info",
	int32(logging.DEBUG):   "debug",
}

var idToLevel = func() map[string]int32 {
	m := make(map[string]int32)
	for k, v := range levelToId {
		m[v] = k
	}
	return m
}()

func loadConfig(win *gtk.Window, b *builder, dbus *dbusObject) {
	var levelCombo *gtk.ComboBoxText
	var redactCheck *gtk.CheckButton

	b.getItems(
		"level_combo", &levelCombo,
		"redact_checkbox", &redactCheck,
	)

	conf, err := dbus.getConfig()
	if err != nil {
		failDialog(win, "Failed to load config from fw daemon: %v", err)
	}

	if lvl, ok := conf["loglevel"].(int32); ok {
		if id, ok := levelToId[lvl]; ok {
			levelCombo.SetActiveID(id)
		}
	}
	if v, ok := conf["logredact"].(bool); ok {
		redactCheck.SetActive(v)
	}
	b.ConnectSignals(map[string]interface{}{
		"on_level_combo_changed": func() {
			if lvl, ok := idToLevel[levelCombo.GetActiveID()]; ok {
				dbus.setConfig("loglevel", lvl)
			}
		},
		"on_redact_checkbox_toggled": func() {
			dbus.setConfig("logredact", redactCheck.GetActive())
		},
	})

}
