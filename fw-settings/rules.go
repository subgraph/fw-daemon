package main

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/subgraph/fw-daemon/sgfw"

	"github.com/gotk3/gotk3/gtk"
	"github.com/gotk3/gotk3/glib"
)

type ruleList struct {
	lock *sync.Mutex
	app        *fwApp
	mode  sgfw.RuleMode
	rows  []*ruleRow
	rules []sgfw.DbusRule
	rowsByIndex   map[int]*ruleRow
	list  *gtk.ListBox
	col0  *gtk.SizeGroup
	col1  *gtk.SizeGroup
	col2  *gtk.SizeGroup
	col3  *gtk.SizeGroup
	raHandlerID glib.SignalHandle
}

type ruleRow struct {
	*gtk.ListBoxRow
	rl              *ruleList
	rule            *sgfw.DbusRule
	gtkBox          *gtk.Box
	gtkSep          *gtk.Separator
	gtkGrid         *gtk.Grid
	gtkLabelApp     *gtk.Label
	gtkLabelTarget  *gtk.Label
	gtkButtonEdit   *gtk.Button
	gtkButtonSave   *gtk.Button
	gtkButtonDelete *gtk.Button
	gtkAppIcon      *gtk.Image
	gtkIconVerb     *gtk.Image
}

func newRuleList(app *fwApp, list *gtk.ListBox, mode sgfw.RuleMode) *ruleList {
	rl := &ruleList{app: app, list: list}
	rl.lock = new(sync.Mutex)
	rl.mode = mode
	rl.list.SetSelectionMode(gtk.SELECTION_NONE)
	rl.col0, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	rl.col1, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	rl.col2, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	rl.col3, _ = gtk.SizeGroupNew(gtk.SIZE_GROUP_HORIZONTAL)
	rl.list.SetActivateOnSingleClick(false)
	return rl
}

func (rl *ruleList) loadRules(noAdd bool) error {
	rl.lock.Lock()
	defer rl.lock.Unlock()
	rules, err := rl.app.Dbus.listRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %+v\n", err)
		return err
	}

	for i := (len(rules) - 1); i >= 0; i-- {
		if sgfw.RuleMode(rules[i].Mode) != rl.mode {
			rules = append(rules[:i], rules[i+1:]...)
		}
	}
	rules = rl.sortRules(rules)
	rl.rules = rules
	if !noAdd {
		rl.addRules(rules)
	}
	return nil
}

func (rl *ruleList) reloadRules(filter string) {
	rl.lock.Lock()
	defer rl.lock.Unlock()
	filter = strings.ToLower(filter)
	rules := make([]sgfw.DbusRule, len(rl.rules))
	copy(rules, rl.rules)
	if filter != "" {
		for i := (len(rules) - 1); i >= 0; i-- {
			if !strings.Contains(strings.ToLower(rules[i].Path), filter) && !strings.Contains(strings.ToLower(rules[i].Sandbox), filter) {
				rules = append(rules[:i], rules[i+1:]...)
			}
		}
	}
	rules = rl.sortRules(rules)

	for i, _ := range rl.rows {
		rl.col0.RemoveWidget(rl.rows[i].gtkAppIcon)
		rl.col1.RemoveWidget(rl.rows[i].gtkLabelApp)
		rl.col2.RemoveWidget(rl.rows[i].gtkIconVerb)
		rl.col3.RemoveWidget(rl.rows[i].gtkLabelTarget)

		rl.rows[i].gtkLabelApp.Destroy()
		rl.rows[i].gtkLabelApp = nil
		rl.rows[i].gtkLabelTarget.Destroy()
		rl.rows[i].gtkLabelTarget = nil
		rl.rows[i].gtkButtonEdit.Destroy()
		rl.rows[i].gtkButtonEdit = nil
		rl.rows[i].gtkButtonSave.Destroy()
		rl.rows[i].gtkButtonSave = nil
		rl.rows[i].gtkButtonDelete.Destroy()
		rl.rows[i].gtkButtonDelete = nil
		rl.rows[i].gtkAppIcon.Destroy()
		rl.rows[i].gtkAppIcon = nil
		rl.rows[i].gtkIconVerb.Destroy()
		rl.rows[i].gtkIconVerb = nil

		rl.rows[i].gtkGrid.Destroy()
		rl.rows[i].gtkGrid = nil
		rl.rows[i].gtkSep.Destroy()
		rl.rows[i].gtkSep = nil
		rl.rows[i].gtkBox.Destroy()
		rl.rows[i].gtkBox = nil

		rl.list.Remove(rl.rows[i])
		rl.rows[i].ListBoxRow.Destroy()
		rl.rows[i].ListBoxRow = nil
		//rl.rows[i].Destroy()
		rl.rows[i].rule = nil
		rl.rows[i].rl = nil
		rl.rows[i] = nil
	}
	rl.rows = rl.rows[:0]
	for i, _ := range rl.rowsByIndex {
		delete(rl.rowsByIndex, i)
	}
	rules = rl.sortRules(rules)
	rl.addRules(rules)
}

func (rl *ruleList) addRules(rules []sgfw.DbusRule) {
	pi := 0
	rl.rowsByIndex = make(map[int]*ruleRow, len(rules))
	if rl.raHandlerID > 0 {
		rl.list.HandlerDisconnect(rl.raHandlerID)
	}
	for i := 0; i < len(rules); i++ {
		row := rl.createWidget(&rules[i])
		rl.col0.AddWidget(row.gtkAppIcon)
		rl.col1.AddWidget(row.gtkLabelApp)
		rl.col2.AddWidget(row.gtkIconVerb)
		rl.col3.AddWidget(row.gtkLabelTarget)
		rl.list.Add(row)
		rl.rowsByIndex[row.GetIndex()] = row
		row.ShowAll()
		if i > 0 && rules[pi].Path == rules[i].Path && rules[pi].Sandbox == rules[i].Sandbox {
			row.hideTitle()
		}
		rl.rows = append(rl.rows, row)
		pi = i
	}
	rl.raHandlerID, _ = rl.list.Connect("row-activated", rl.showInformation)
}

func (rl *ruleList) createWidget(rule *sgfw.DbusRule) *ruleRow {
	row := &ruleRow{rl: rl}
	row.rule = rule
	builder := newBuilder("RuleItem")
	builder.getItems(
		"grid", &row.gtkGrid,
		"app_label", &row.gtkLabelApp,
		"verb_icon", &row.gtkIconVerb,
		"target_label", &row.gtkLabelTarget,
		"edit_button", &row.gtkButtonEdit,
		"save_button", &row.gtkButtonSave,
		"delete_button", &row.gtkButtonDelete,
		"app_icon", &row.gtkAppIcon,
	)
	switch sgfw.RuleMode(rule.Mode) {
	case sgfw.RULE_MODE_SYSTEM:
		row.gtkButtonEdit.SetVisible(false)
		row.gtkButtonEdit.SetNoShowAll(true)
		row.gtkButtonDelete.SetSensitive(false)
		row.gtkButtonDelete.SetTooltipText("Cannot delete system rules")
		break
	case sgfw.RULE_MODE_PROCESS:
		row.gtkButtonSave.SetSensitive(true)
		row.gtkButtonSave.SetNoShowAll(false)
		break
	case sgfw.RULE_MODE_SESSION:
		row.gtkButtonSave.SetSensitive(true)
		row.gtkButtonSave.SetNoShowAll(false)
		break
	}

	builder.ConnectSignals(map[string]interface{}{
		"on_edit_rule":   row.onEdit,
		"on_save_rule":   row.onSaveAsNew,
		"on_delete_rule": row.onDelete,
	})
	row.gtkBox, _ = gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 0)
	row.gtkSep, _ = gtk.SeparatorNew(gtk.ORIENTATION_HORIZONTAL)
	row.ListBoxRow, _ = gtk.ListBoxRowNew()
	row.gtkBox.Add(row.gtkGrid)
	row.gtkBox.Add(row.gtkSep)
	row.Add(row.gtkBox)
	row.SetProperty("selectable", false)
	row.SetProperty("activatable", true)
	row.showTitle()
	row.update()
	//builder.Object.Unref()
	builder = nil
	return row
}

func (rl *ruleList) showInformation(list *gtk.ListBox, row *gtk.ListBoxRow) bool {
	rr := rl.rowsByIndex[row.GetIndex()]
	rr.runNewEditor(DIALOG_MODE_INFO)
	return true
}

func (rr *ruleRow) update() {
	rr.gtkLabelApp.SetTooltipText(rr.rule.Path)
	rr.setVerbIcon()
	tt := getTargetText(rr.rule)
	if rr.rule.UID > -1 || rr.rule.GID > -1 {
		tt = tt + " for "
	}
	if rr.rule.UID > -1 {
		tt = tt + rr.rl.app.LookupUsername(rr.rule.UID)
	}
	if rr.rule.UID > -1 && rr.rule.GID > -1 {
		tt = tt + ":"
	}
	if rr.rule.GID > -1 {
		tt = tt + rr.rl.app.LookupGroup(rr.rule.GID)
	}
	rr.gtkLabelTarget.SetText(tt)
}

func (rr *ruleRow) hideTitle() {
	rr.gtkLabelApp.SetText("")
	rr.gtkAppIcon.Clear()
}

func (rr *ruleRow) showTitle() {
	in := []string{rr.rule.App}
	if rr.rule.Sandbox != "" {
		in = append([]string{rr.rule.Sandbox}, in...)
	}
	if rr.rule.App == "[unknown]" {
		in = []string{"image-missing"}
	}
	it, err := gtk.IconThemeGetDefault()
	if err != nil {
		fmt.Println("Error getting icon theme.")
	} else {
		found := false
		for _, ia := range in {
			pb, _ := it.LoadIcon(ia, int(gtk.ICON_SIZE_BUTTON), gtk.ICON_LOOKUP_USE_BUILTIN)
			if pb != nil {
				rr.gtkAppIcon.SetFromIconName(ia, gtk.ICON_SIZE_BUTTON)
				found = true
				break
			}
		}
		if !found {
			rr.gtkAppIcon.SetFromIconName("terminal", gtk.ICON_SIZE_BUTTON)
		}
	}
	rr.gtkLabelApp.SetText(rr.rule.App)
}

func (rr *ruleRow) setVerbIcon() {
	it, err := gtk.IconThemeGetDefault()
	in := ""
	tt := ""
	if sgfw.RuleAction(rr.rule.Verb) == sgfw.RULE_ACTION_DENY {
		in = "gtk-no"
		tt = "Deny"
	} else if sgfw.RuleAction(rr.rule.Verb) == sgfw.RULE_ACTION_ALLOW {
		in = "gtk-yes"
		tt = "Allow"
	} else if sgfw.RuleAction(rr.rule.Verb) == sgfw.RULE_ACTION_ALLOW_TLSONLY {
		in = "gtk-yes"
		tt = "Allow TLS"
	}
	if err != nil {
		fmt.Println("Error getting icon theme.")
		return
	}
	pb, _ := it.LoadIcon(in, int(gtk.ICON_SIZE_BUTTON), gtk.ICON_LOOKUP_USE_BUILTIN)
	if pb == nil {
		fmt.Println("Error getting icon theme.")
		return
	}
	rr.gtkIconVerb.SetFromIconName(in, gtk.ICON_SIZE_BUTTON)
	rr.gtkIconVerb.SetTooltipText(tt)
}

func getVerbText(rule *sgfw.DbusRule) string {
	if sgfw.RuleAction(rule.Verb) == sgfw.RULE_ACTION_ALLOW {
		return sgfw.RuleActionString[sgfw.RULE_ACTION_ALLOW] + ":"
	}
	if sgfw.RuleAction(rule.Verb) == sgfw.RULE_ACTION_ALLOW_TLSONLY {
		return sgfw.RuleActionString[sgfw.RULE_ACTION_ALLOW_TLSONLY] + ":"
	}
	return sgfw.RuleActionString[sgfw.RULE_ACTION_DENY] + ":"
}

func getTargetText(rule *sgfw.DbusRule) string {
	verb := "Deny"
	if sgfw.RuleAction(rule.Verb) == sgfw.RULE_ACTION_ALLOW || sgfw.RuleAction(rule.Verb) == sgfw.RULE_ACTION_ALLOW_TLSONLY {
		verb = "Allow"
	}
	if rule.Target == "*:*" {
		ct := "any"
		if sgfw.RuleAction(rule.Verb) == sgfw.RULE_ACTION_DENY {
			ct = "all"
		}
		res := []string{verb, ct, "connections"}
		if sgfw.RuleAction(rule.Verb) == sgfw.RULE_ACTION_ALLOW_TLSONLY {
			res = append(res, "with TLS")
		}
		return strings.Join(res, " ")
	}

	items := strings.Split(rule.Target, ":")
	if len(items) != 2 {
		return strings.Join([]string{verb, rule.Target}, " ")
	}

	ct := "connections"
	if rule.Proto != "tcp" {
		ct = "data"
	}
	target := []string{verb, strings.ToUpper(rule.Proto), ct}
	if sgfw.RuleAction(rule.Verb) == sgfw.RULE_ACTION_ALLOW_TLSONLY {
		target = append(target, "with TLS")
	}
	if rule.Origin != "" {
		target = append(target, "from ", rule.Origin)
	}
	if items[0] == "*" {
		if rule.Proto == "tcp" {
			target = append(target, fmt.Sprintf("to ALL hosts on port %s", items[1]))
		} else if rule.Proto == "icmp" {
			target = append(target, fmt.Sprintf("to ALL hosts with code %s", items[1]))
		} else {
			target = append(target, fmt.Sprintf("to ALL hosts on port %s", items[1]))
		}
		return strings.Join(target, " ")
	}
	if items[1] == "*" {
		if rule.Proto == "tcp" {
			target = append(target, fmt.Sprintf("to host %s", items[0]))
		} else if rule.Proto == "icmp" {
			target = append(target, fmt.Sprintf("to host %s", items[0]))
		} else {
			target = append(target, fmt.Sprintf("to host %s", items[0]))
		}
		return strings.Join(target, " ")
	}
	ps := "port"
	if rule.Proto == "icmp" {
		ps = "code"
	}
	target = append(target, fmt.Sprintf("to %s on %s %s", items[0], ps, items[1]))

	return strings.Join(target, " ")
}

func (rr *ruleRow) onSaveAsNew() {
	rr.runNewEditor(DIALOG_MODE_SAVEAS)
}

func (rr *ruleRow) onEdit() {
	rr.runNewEditor(DIALOG_MODE_EDIT)
}

func (rr *ruleRow) onDelete() {
	var body string
	if rr.rule.Sandbox != "" {
		ss := `Are you sure you want to delete this rule:

<b>Path:</b>   %s

<b>Sandbox:</b>   %s

<b>Rule:</b>   %s`
		body = fmt.Sprintf(ss, rr.rule.Path, rr.rule.Sandbox, getTargetText(rr.rule))
	} else {
		ss := `Are you sure you want to delete this rule:

<b>Path:</b>   %s

<b>Rule:</b>   %s`
		body = fmt.Sprintf(ss, rr.rule.Path, getTargetText(rr.rule))
	}
	d := gtk.MessageDialogNewWithMarkup(
		rr.rl.app.win,
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
	rl.col0.RemoveWidget(rr.gtkAppIcon)
	rl.col1.RemoveWidget(rr.gtkLabelApp)
	rl.col2.RemoveWidget(rr.gtkIconVerb)
	rl.col3.RemoveWidget(rr.gtkLabelTarget)
	rl.list.Remove(rr.ListBoxRow)
	for i := (len(rl.rules) - 1); i >= 0; i-- {
		if *rr.rule == rl.rules[i] {
			rl.rules = append(rl.rules[:i], rl.rules[i+1:]...)
			break;
		}
	}

}

func (rr *ruleRow) delete() {
	idx := rr.ListBoxRow.GetIndex()
	ndx := idx + 1
	pdx := idx - 1
	if ndx < len(rr.rl.rows) {
		if pdx != -1 {
			if rr.rl.rows[pdx].rule.Path != rr.rule.Path || rr.rl.rows[pdx].rule.Sandbox != rr.rule.Sandbox {
				rr.rl.rows[ndx].showTitle()
			}
		} else {
			rr.rl.rows[ndx].showTitle()
		}
	}
	rr.rl.remove(rr)
	rr.rl.app.Dbus.deleteRule(rr.rule.ID)
	rr.rl.rows = append(rr.rl.rows[:idx], rr.rl.rows[idx+1:]...)
}
