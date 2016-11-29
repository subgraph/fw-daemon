package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/subgraph/fw-daemon/sgfw"

	"github.com/gotk3/gotk3/gtk"
)

type ruleList struct {
	dbus *dbusObject
	win  *gtk.Window
	list *gtk.ListBox
	col1 *gtk.SizeGroup
	col2 *gtk.SizeGroup
	col3 *gtk.SizeGroup
}

type ruleRow struct {
	rl            *ruleList
	rule          *sgfw.DbusRule
	widget        *gtk.ListBoxRow
	app_label     *gtk.Label
	verb_label    *gtk.Label
	target_label  *gtk.Label
	edit_button   *gtk.Button
	save_button   *gtk.Button
	delete_button *gtk.Button
}

func NewRuleList(dbus *dbusObject, win *gtk.Window, list *gtk.ListBox) *ruleList {
	rl := &ruleList{dbus: dbus, win: win, list: list}
	rl.list.SetSelectionMode(gtk.SELECTION_NONE)
	rl.col1, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	rl.col2, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	rl.col3, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	return rl
}

func (rl *ruleList) loadRules(mode sgfw.RuleMode) error {
	rules, err := rl.dbus.listRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %+v\n", err)
		return err
	}
	rl.addRules(rules, mode)
	return nil
}

func (rl *ruleList) addRules(rules []sgfw.DbusRule, mode sgfw.RuleMode) {
	for i := 0; i < len(rules); i++ {
		if sgfw.RuleMode(rules[i].Mode) != mode {
			continue
		}
		row := createWidget(&rules[i])
		row.rl = rl
		rl.col1.AddWidget(row.app_label)
		rl.col2.AddWidget(row.verb_label)
		rl.col3.AddWidget(row.target_label)
		rl.list.Add(row.widget)
	}
}

func createWidget(rule *sgfw.DbusRule) *ruleRow {
	row := &ruleRow{}
	row.rule = rule
	builder := newBuilder("RuleItem")
	var grid *gtk.Grid
	builder.getItems(
		"grid", &grid,
		"app_label", &row.app_label,
		"verb_label", &row.verb_label,
		"target_label", &row.target_label,
		"edit_button", &row.edit_button,
		"save_button", &row.save_button,
		"delete_button", &row.delete_button,
	)
	switch sgfw.RuleMode(rule.Mode) {
	case sgfw.RULE_MODE_SYSTEM:
		row.edit_button.SetVisible(false)
		row.edit_button.SetNoShowAll(true)
		row.delete_button.SetSensitive(false)
		row.delete_button.SetTooltipText("Cannot delete system rules")
		break
	case sgfw.RULE_MODE_SESSION:
		row.save_button.SetSensitive(true)
		row.save_button.SetNoShowAll(false)
		break
	}

	builder.ConnectSignals(map[string]interface{}{
		"on_edit_rule":   row.onEdit,
		"on_save_rule":   row.onSaveAsNew,
		"on_delete_rule": row.onDelete,
	})
	row.widget, _ = gtk.ListBoxRowNew()
	row.widget.Add(grid)
	row.update()
	return row
}

func (rr *ruleRow) update() {
	rr.app_label.SetText(rr.rule.App)
	rr.app_label.SetTooltipText(rr.rule.Path)
	rr.verb_label.SetText(getVerbText(rr.rule))
	rr.target_label.SetText(getTargetText(rr.rule))
}

func getVerbText(rule *sgfw.DbusRule) string {
	if sgfw.RuleAction(rule.Verb) == sgfw.RULE_ACTION_ALLOW {
		return sgfw.RuleActionString[sgfw.RULE_ACTION_ALLOW] + ":"
	}
	return sgfw.RuleActionString[sgfw.RULE_ACTION_DENY] + ":"
}

func getTargetText(rule *sgfw.DbusRule) string {
	if rule.Target == "*:*" {
		return "All connections"
	}
	items := strings.Split(rule.Target, ":")

	if len(items) != 2 {
		return rule.Target
	}

	if items[0] == "*" {
		return fmt.Sprintf("Connections to All hosts on port %s", items[1])
	}
	if items[1] == "*" {
		return fmt.Sprintf("All connections to host %s", items[0])
	}

	return fmt.Sprintf("Connections to %s on port %s", items[0], items[1])
}

func (rr *ruleRow) onSaveAsNew() {
	rr.runEditor(true)
}

func (rr *ruleRow) onEdit() {
	rr.runEditor(false)
}

func (rr *ruleRow) onDelete() {
	body := fmt.Sprintf(`Are you sure you want to delete this rule:

	<b>Path:</b>   %s

	<b>Rule:</b>   %s %s`, rr.rule.Path, getVerbText(rr.rule), getTargetText(rr.rule))
	d := gtk.MessageDialogNewWithMarkup(
		rr.rl.win,
		gtk.DIALOG_DESTROY_WITH_PARENT,
		gtk.MESSAGE_QUESTION,
		gtk.BUTTONS_OK_CANCEL,
		"")
	d.SetMarkup(body)
	if d.Run() == (int)(gtk.RESPONSE_OK) {
		rr.delete()
	}
	d.Destroy()

}

func (rl *ruleList) remove(rr *ruleRow) {
	rl.col1.RemoveWidget(rr.app_label)
	rl.col2.RemoveWidget(rr.verb_label)
	rl.col3.RemoveWidget(rr.target_label)
	rl.list.Remove(rr.widget)
}

func (rr *ruleRow) delete() {
	rr.rl.remove(rr)
	rr.rl.dbus.deleteRule(rr.rule.Id)
}
