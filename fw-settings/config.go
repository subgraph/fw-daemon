package main

import (
	"github.com/gotk3/gotk3/gtk"
	"github.com/op/go-logging"
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

var actionToId = map[int32]string{
	0: "ONCE",
	1: "SESSION",
	3: "FOREVER",
}

var idToAction = func() map[string]int32 {
	m := make(map[string]int32)
	for k, v := range actionToId {
		m[v] = k
	}
	return m
}()

func loadConfig(win *gtk.Window, b *builder, dbus *dbusObject) {
	var levelCombo *gtk.ComboBoxText
	var redactCheck *gtk.CheckButton
	var expandedCheck *gtk.CheckButton
	var expertCheck *gtk.CheckButton
	var actionCombo *gtk.ComboBoxText

	b.getItems(
		"level_combo", &levelCombo,
		"redact_checkbox", &redactCheck,
		"expanded_checkbox", &expandedCheck,
		"expert_checkbox", &expertCheck,
		"action_combo", &actionCombo,
	)

	conf, err := dbus.getConfig()
	if err != nil {
		failDialog(win, "Failed to load config from fw daemon: %v", err)
	}

	if lvl, ok := conf["log_level"].(int32); ok {
		if id, ok := levelToId[lvl]; ok {
			levelCombo.SetActiveID(id)
		}
	}
	if v, ok := conf["log_redact"].(bool); ok {
		redactCheck.SetActive(v)
	}
	if v, ok := conf["prompt_expanded"].(bool); ok {
		expandedCheck.SetActive(v)
	}
	if v, ok := conf["prompt_expert"].(bool); ok {
		expertCheck.SetActive(v)
	}
	if av, ok := conf["default_action"].(int32); ok {
		if id, ok := actionToId[av]; ok {
			actionCombo.SetActiveID(id)
		}
	}
	b.ConnectSignals(map[string]interface{}{
		"on_level_combo_changed": func() {
			if lvl, ok := idToLevel[levelCombo.GetActiveID()]; ok {
				dbus.setConfig("log_level", lvl)
			}
		},
		"on_redact_checkbox_toggled": func() {
			dbus.setConfig("log_redact", redactCheck.GetActive())
		},
		"on_expanded_checkbox_toggled": func() {
			dbus.setConfig("prompt_expanded", expandedCheck.GetActive())
		},
		"on_expert_checkbox_toggled": func() {
			dbus.setConfig("prompt_expert", expertCheck.GetActive())
		},
		"on_action_combo_changed": func() {
			if al, ok := idToAction[actionCombo.GetActiveID()]; ok {
				dbus.setConfig("default_action", al)
			}
		},
	})

}
