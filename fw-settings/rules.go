package main

import (
	"fmt"
	"github.com/subgraph/fw-daemon/Godeps/_workspace/src/github.com/gotk3/gotk3/gtk"
	"strings"
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
	rl           *ruleList
	rule         *dbusRule
	widget       *gtk.ListBoxRow
	app_label    *gtk.Label
	verb_label   *gtk.Label
	target_label *gtk.Label
}

func NewRuleList(dbus *dbusObject, win *gtk.Window, list *gtk.ListBox) *ruleList {
	rl := &ruleList{dbus: dbus, win: win, list: list}
	rl.col1, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	rl.col2, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	rl.col3, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	return rl
}

func (rl *ruleList) loadRules() error {
	rules, err := rl.dbus.listRules()
	if err != nil {
		return err
	}
	rl.addRules(rules)
	return nil
}

func (rl *ruleList) addRules(rules []dbusRule) {
	for i := 0; i < len(rules); i++ {
		row := createWidget(&rules[i])
		row.rl = rl
		rl.col1.AddWidget(row.app_label)
		rl.col2.AddWidget(row.verb_label)
		rl.col3.AddWidget(row.target_label)
		rl.list.Add(row.widget)
	}
}

const RULE_DENY = 0
const RULE_ALLOW = 1

func createWidget(rule *dbusRule) *ruleRow {
	row := &ruleRow{}
	row.rule = rule
	builder := newBuilder("RuleItem")
	var grid *gtk.Grid
	builder.getItems(
		"grid", &grid,
		"app_label", &row.app_label,
		"verb_label", &row.verb_label,
		"target_label", &row.target_label,
	)
	builder.ConnectSignals(map[string]interface{}{
		"on_edit_rule":   row.onEdit,
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

func getVerbText(rule *dbusRule) string {
	if rule.Verb == RULE_ALLOW {
		return "ALLOW:"
	}
	return "DENY:"
}

func getTargetText(rule *dbusRule) string {
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
		return fmt.Sprintf("All connections to host %s")
	}

	return fmt.Sprintf("Connections to %s on port %s", items[0], items[1])
}

func (rr *ruleRow) onEdit() {
	rr.runEditor()
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
