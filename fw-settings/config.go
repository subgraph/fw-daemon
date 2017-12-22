package main

import (
	"github.com/subgraph/fw-daemon/sgfw"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

type cbConfigChanged func()
var configCallbacks []cbConfigChanged

func (fa *fwApp) loadConfig(init bool) {
	var levelCombo *gtk.ComboBoxText
	var redactCheck *gtk.CheckButton
	var expandedCheck *gtk.CheckButton
	var expertCheck *gtk.CheckButton
	var actionCombo *gtk.ComboBoxText
	var gridPrompt *gtk.Grid
	var toplevelCheck *gtk.CheckButton

	fa.winb.getItems(
		"level_combo", &levelCombo,
		"redact_checkbox", &redactCheck,
		"expanded_checkbox", &expandedCheck,
		"expert_checkbox", &expertCheck,
		"action_combo", &actionCombo,
		"grib_gtkprompt", &gridPrompt,
		"toplevel_checkbox", &toplevelCheck,
	)

	conf, err := fa.Dbus.getConfig()
	if err != nil {
		failDialog(&fa.win.Window, "Failed to load config from fw daemon: %v", err)
	}

	if lvl, ok := conf["log_level"].(int32); ok {
		if id, ok := sgfw.LevelToID[lvl]; ok {
			levelCombo.SetActiveID(id)
		}
	}
	if v, ok := conf["log_redact"].(bool); ok {
		redactCheck.SetActive(v)
	}
	if v, ok := conf["prompt_expanded"].(bool); ok {
		fa.Config.PromptExpanded = v
		expandedCheck.SetActive(v)
	}
	if v, ok := conf["prompt_expert"].(bool); ok {
		fa.Config.PromptExpert = v
		expertCheck.SetActive(v)
	}
	if av, ok := conf["default_action"].(uint16); ok {
		v := sgfw.GetFilterScopeString(sgfw.FilterScope(av))
		fa.Config.DefaultAction = v
		actionCombo.SetActiveID(v)
	}

	if fa.promptMode == promptModeDisabled {
		gridPrompt.SetNoShowAll(true)
		gridPrompt.SetVisible(false)
		expertCheck.SetTooltipText("")
	} else {
		l := expertCheck.GetChildren()
		ect, _ := expertCheck.GetLabel()
		ecl := gtk.Label{*l.NthData(0).(*gtk.Widget)}
		ecl.SetUseMarkup(true)
		ecl.SetMarkup("<s>" + ect + "</s>")
		expertCheck.SetTooltipText("Applies only when using the GNOME Shell Prompter")

		gridPrompt.SetNoShowAll(false)
		gridPrompt.SetVisible(true)
		toplevelCheck.SetActive(fa.Settings.GetToplevelPrompt())
	}

	if init {
		levelCombo.Connect("changed", func() {
			if lvl, ok := sgfw.IDToLevel[levelCombo.GetActiveID()]; ok {
				fa.Dbus.setConfig("log_level", lvl)
			}
		})
		var redactHandler glib.SignalHandle
		redactHandler, _ = redactCheck.Connect("toggled", func() {
			val := redactCheck.GetActive()
			if val {
				fa.Dbus.setConfig("log_redact", val)
				return
			}
			if fa.promptWarnLogRedact() {
				fa.Dbus.setConfig("log_redact", val)
			} else {
				redactCheck.HandlerBlock(redactHandler)
				redactCheck.SetActive(true)
				redactCheck.HandlerUnblock(redactHandler)
			}
		})
		expandedCheck.Connect("toggled", func() {
			v := expandedCheck.GetActive()
			fa.Config.PromptExpanded = v
			fa.Dbus.setConfig("prompt_expanded", v)
			fa.triggerConfigCallbacks()
		})
		expertCheck.Connect("toggled", func() {
				v := expertCheck.GetActive()
				fa.Config.PromptExpert = v
				fa.Dbus.setConfig("prompt_expert", v)
				fa.triggerConfigCallbacks()
		})
		actionCombo.Connect("changed", func() {
				v := sgfw.GetFilterScopeValue(actionCombo.GetActiveID())
				fa.Config.DefaultAction = string(sgfw.FilterScope(v))
				fa.Dbus.setConfig("default_action", v)
				fa.triggerConfigCallbacks()
		})
		if fa.promptMode != promptModeDisabled {
			toplevelCheck.Connect("toggled", func() {
				fa.Settings.SetToplevelPrompt(toplevelCheck.GetActive())
			})
		}
	}
}

func (fa *fwApp) promptWarnLogRedact() bool {
	res := false
	body := "Are you sure you want to unredact logs?"
	msg := "Sensitive information may get saved to the disk!"
	d := gtk.MessageDialogNewWithMarkup(
		fa.win,
		gtk.DIALOG_DESTROY_WITH_PARENT,
		gtk.MESSAGE_QUESTION,
		gtk.BUTTONS_OK_CANCEL,
		"")
	d.SetMarkup(body)
	d.SetProperty("secondary-text", msg)
	if d.Run() == (int)(gtk.RESPONSE_OK) {
		res = true
	} else {
		fa.win.SetUrgencyHint(false)
		fa.win.SetKeepAbove(false)
	}
	d.Destroy()
	return res
}

func (fa *fwApp) appendConfigCallback(fn cbConfigChanged) {
	configCallbacks = append(configCallbacks, fn)
}

func (fa *fwApp) triggerConfigCallbacks() {
	for _, fn := range configCallbacks {
		glib.IdleAdd(func () bool {
			fn()
			return false
		})
	}
}
