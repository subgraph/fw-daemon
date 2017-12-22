package main

import (
	"fmt"
	"os"
	"strings"
	"strconv"
	"unicode"

	"github.com/subgraph/fw-daemon/sgfw"

	"github.com/gotk3/gotk3/gtk"
)

const (
	newDialogCancel = 1
	newDialogOk     = 2
	newDialogAllow  = 3
)

const (
	COLUMN_ID = iota
	COLUMN_NAME
)

type DialogMode uint

const (
	DIALOG_MODE_NEW DialogMode = iota
	DIALOG_MODE_EDIT
	DIALOG_MODE_SAVEAS
	DIALOG_MODE_PROMPT
	DIALOG_MODE_INFO
)

const (
	Setuid uint32 = 1 << (12 - 1 - iota)
	Setgid
	Sticky
	UserRead
	UserWrite
	UserExecute
	GroupRead
	GroupWrite
	GroupExecute
	OtherRead
	OtherWrite
	OtherExecute
)

type ruleNew struct {
	dialog     *gtk.Dialog
	row        *ruleRow
	mode       DialogMode
	nbSelected int
	comboUID   *gtk.ComboBoxText
	checkUID   *gtk.CheckButton
	comboGID   *gtk.ComboBoxText
	checkGID   *gtk.CheckButton
	titleScope *gtk.Label
	comboScope *gtk.ComboBoxText
	labelScope *gtk.Label
	comboVerb  *gtk.ComboBoxText
	checkTLS   *gtk.CheckButton
	titleSandbox *gtk.Label
	labelSandbox *gtk.Label
	comboSandbox *gtk.ComboBoxText
	btnPathChooser *gtk.FileChooserButton
	entryPath *gtk.Entry
	hostEntry    *gtk.Entry
	portEntry    *gtk.Entry
	titlePort *gtk.Label
	comboProto *gtk.ComboBoxText
	ok *gtk.Button
	allow *gtk.Button
	cancel *gtk.Button
	labelPID *gtk.Label
	titlePID *gtk.Label
	entryOrigin *gtk.Entry
	labelOrigin *gtk.Label
}

func newRuleAdd(rr *ruleRow, mode DialogMode) *ruleNew{
	rnew := &ruleNew{}
	rnew.mode = mode
	rnew.nbSelected = rr.rl.app.nbRules.GetCurrentPage()
	b := newBuilder("RuleNew")
	b.getItems(
		"dialog", &rnew.dialog,
		"uid_combo", &rnew.comboUID,
		"uid_checkbox", &rnew.checkUID,
		"gid_combo", &rnew.comboGID,
		"gid_checkbox", &rnew.checkGID,
		"scope_title", &rnew.titleScope,
		"scope_combo", &rnew.comboScope,
		"scope_label", &rnew.labelScope,
		"verb_combo", &rnew.comboVerb,
		"tls_check", &rnew.checkTLS,
		"sandbox_title", &rnew.titleSandbox,
		"sandbox_combo", &rnew.comboSandbox,
		"sandbox_label", &rnew.labelSandbox,
		"path_chooser", &rnew.btnPathChooser,
		"path_entry", &rnew.entryPath,
		"host_entry", &rnew.hostEntry,
		"port_entry", &rnew.portEntry,
		"port_title", &rnew.titlePort,
		"proto_combo", &rnew.comboProto,
		"ok_button", &rnew.ok,
		"allow_button", &rnew.allow,
		"cancel_button", &rnew.cancel,
		"pid_label", &rnew.labelPID,
		"pid_title", &rnew.titlePID,
		"origin_entry", &rnew.entryOrigin,
		"origin_label", &rnew.labelOrigin,
	)

	b.ConnectSignals(map[string]interface{}{
		"on_proto_changed":    rnew.onProtoChanged,
		"on_verb_changed":     rnew.onVerbChanged,
		"on_port_insert_text": rnew.onPortInsertText,
		"on_port_changed":     rnew.onChanged,
		"on_host_changed":     rnew.onChanged,
		"on_path_changed":     rnew.onChanged,
		"on_path_set":         rnew.onPathSet,
	})

	rnew.row = rr
	switch rnew.mode {
	case DIALOG_MODE_EDIT:
		rnew.dialog.SetTitle("Edit Rule")
	case DIALOG_MODE_NEW:
		rnew.dialog.SetTitle("Add New Rule")
	case DIALOG_MODE_SAVEAS:
		rnew.ok.SetLabel("Save As New")
		rnew.dialog.SetTitle("Save As New Rule")
	case DIALOG_MODE_PROMPT:
		rnew.connectShortcutsPromptWindow()
		rnew.dialog.SetTitle("Firewall Prompt")
	case DIALOG_MODE_INFO:
		rnew.cancel.SetLabel("Close")
		rnew.dialog.SetTitle("Rule Information")
	}

	return rnew
}

func (re *ruleNew) connectShortcutsPromptWindow() {
	app := re.row.rl.app
	// Shortcuts Help Registered in Prompt
	app.ConnectShortcut("<Alt>h", "", "", re.dialog.Window, func(win gtk.Window) {re.hostEntry.Widget.GrabFocus()})
	app.ConnectShortcut("<Alt>p", "", "", re.dialog.Window, func(win gtk.Window) {re.portEntry.Widget.GrabFocus()})
	app.ConnectShortcut("<Alt>o", "", "", re.dialog.Window, func(win gtk.Window) {re.comboProto.ComboBox.Popup()})
	app.ConnectShortcut("<Alt>t", "", "", re.dialog.Window, func(win gtk.Window) {
		if re.checkTLS.GetSensitive() {
			re.checkTLS.SetActive(!re.checkTLS.GetActive())
		}
	})
	app.ConnectShortcut("<Alt>s", "", "", re.dialog.Window, func(win gtk.Window) {re.comboScope.ComboBox.Popup()})
	app.ConnectShortcut("<Alt>u", "", "", re.dialog.Window, func(win gtk.Window) {re.checkUID.SetActive(!re.checkUID.GetActive())})
	app.ConnectShortcut("<Alt>g", "", "", re.dialog.Window, func(win gtk.Window) {re.checkGID.SetActive(!re.checkGID.GetActive())})
}

func (re *ruleNew) updateRow(res int) {
	if !re.validateFields() {
		return
	}
	r := re.row.rule
	if re.mode == DIALOG_MODE_PROMPT {
		if res == newDialogOk {
			r.Verb = uint16(sgfw.RULE_ACTION_DENY)
		} else if res == newDialogAllow {
			r.Verb = uint16(sgfw.RULE_ACTION_ALLOW)
		}
		mid, _ := strconv.Atoi(re.comboScope.GetActiveID())
		r.Mode = uint16(mid)
	} else {
		switch re.comboVerb.GetActiveID() {
		case "allow":
			r.Verb = uint16(sgfw.RULE_ACTION_ALLOW)
	//	case "allow_tls":
	//		r.Verb = uint16(sgfw.RULE_ACTION_ALLOW_TLSONLY)
		case "deny":
			r.Verb = uint16(sgfw.RULE_ACTION_DENY)
		}
	}

	r.Proto = re.comboProto.GetActiveID()
	if r.Proto == "any" {
		r.Proto = "*"
	}
	if r.Proto == "tcp" && r.Verb == uint16(sgfw.RULE_ACTION_ALLOW) && re.checkTLS.GetActive() {
		r.Verb = uint16(sgfw.RULE_ACTION_ALLOW_TLSONLY)
	}

	host, _ := re.hostEntry.GetText()
	port, _ := re.portEntry.GetText()
	r.Target = fmt.Sprintf("%s:%s", host, port)
	if re.mode != DIALOG_MODE_PROMPT || re.checkUID.GetActive() == true {
		uid, _ := strconv.ParseInt(re.comboUID.GetActiveID(), 10, 32)
		r.UID = int32(uid)
	} else {
		r.UID = -1
	}
	if re.mode != DIALOG_MODE_PROMPT || re.checkGID.GetActive() == true {
		gid, _ := strconv.ParseInt(re.comboGID.GetActiveID(), 10, 32)
		r.GID = int32(gid)
	} else {
		r.GID = -1
	}

	if re.mode == DIALOG_MODE_NEW {
		r.Path = re.btnPathChooser.FileChooser.GetFilename()
		mid, _ := strconv.Atoi(re.comboScope.GetActiveID())
		r.Mode = uint16(mid)
		r.Sandbox = re.comboSandbox.GetActiveID()
	}

	if re.mode != DIALOG_MODE_NEW && re.mode != DIALOG_MODE_PROMPT {
		re.row.update()
	}
}

type cbPromptRequest func(guid string, rule *sgfw.DbusRule)

func (re *ruleNew) run(guid string, cb cbPromptRequest) {
	re.dialog.SetTransientFor(re.row.rl.app.win)
	re.dialog.ShowAll()
	if re.mode == DIALOG_MODE_INFO {
		re.dialog.Run()
	} else if re.mode == DIALOG_MODE_PROMPT {
		res := re.dialog.Run()
		if res != newDialogCancel {
			re.updateRow(res)
			cb(guid, re.row.rule)
		}
	} else if re.mode == DIALOG_MODE_NEW {
		if re.dialog.Run() == newDialogOk {
			re.updateRow(newDialogOk)
			r := *re.row.rule
			res, err := re.row.rl.app.Dbus.addRule(&r)
			if res == false || err != nil {
				warnDialog(&re.row.rl.app.win.Window, "Error notifying SGFW of asynchronous rule addition:", err)
				return
			}
		}
	} else if re.mode == DIALOG_MODE_SAVEAS {
		if re.dialog.Run() == newDialogOk {
			re.updateRow(newDialogOk)
			r := *re.row.rule
			re.row.rl.app.Dbus.addRule(&r)
			re.row.rl.remove(re.row)
		}
	} else {
		if re.dialog.Run() == newDialogOk {
			re.updateRow(newDialogOk)
			re.row.rl.app.Dbus.updateRule(re.row.rule)
		}
	}
	re.dialog.Destroy()
}

func (rr *ruleRow) runNewEditor(mode DialogMode) {
	redit := newRuleAdd(rr, mode)
	redit.update()
	redit.run("", nil)
}

func (re *ruleNew) update() {
	re.populateUID()
	re.populateGID()
	r := re.row.rule

	if re.mode != DIALOG_MODE_INFO {
		re.comboScope.Remove(4)
	}

	if re.mode != DIALOG_MODE_PROMPT && re.mode != DIALOG_MODE_INFO {
		re.comboScope.Remove(3)
		re.comboScope.Remove(2)
	}

	re.onVerbChanged()

	if re.mode == DIALOG_MODE_NEW {
		if re.nbSelected < 2 {
			re.comboScope.SetActive(re.nbSelected)
		} else {
			re.comboScope.SetActive(0)
		}
		//re.titleSandbox.SetNoShowAll(true)
		//re.titleSandbox.SetVisible(false)
		//re.comboSandbox.SetNoShowAll(true)
		//re.comboSandbox.SetVisible(false)
		//re.comboSandbox.SetNoShowAll(true)
		//re.comboSandbox.SetVisible(false)
		re.comboSandbox.Append("", "")
		for _, pn := range re.row.rl.app.ozProfiles {
			re.comboSandbox.Append(pn, pn)
		}
		re.comboSandbox.SetActive(0)
		re.btnPathChooser.SetCurrentFolder("/")
		re.ok.SetSensitive(false)
		re.onProtoChanged()

		return
	}

	if r.Proto == "" {
		re.comboProto.SetActiveID("any")
	} else {
		re.comboProto.SetActiveID(strings.ToLower(r.Proto))
	}

	re.comboSandbox.SetVisible(false)
	re.comboSandbox.SetSensitive(false)
	re.comboSandbox.SetNoShowAll(true)

	if sgfw.RuleAction(r.Verb) == sgfw.RULE_ACTION_ALLOW || sgfw.RuleAction(r.Verb) == sgfw.RULE_ACTION_ALLOW_TLSONLY {
		re.comboVerb.SetActiveID("allow")
	} else {
		re.comboVerb.SetActiveID("deny")
	}

	if sgfw.RuleAction(r.Verb) == sgfw.RULE_ACTION_ALLOW_TLSONLY {
		re.checkTLS.SetActive(true)
	}

	if r.Sandbox == "" {
		re.titleSandbox.SetNoShowAll(true)
		re.titleSandbox.SetVisible(false)
		re.labelSandbox.SetNoShowAll(true)
		re.labelSandbox.SetVisible(false)
	} else {
		re.titleSandbox.SetVisible(true)
		re.labelSandbox.SetNoShowAll(false)
		re.labelSandbox.SetVisible(true)
		re.labelSandbox.SetNoShowAll(false)
		re.labelSandbox.SetText(r.Sandbox)
	}

	re.btnPathChooser.SetNoShowAll(true)
	re.btnPathChooser.SetVisible(false)
	re.btnPathChooser.SetSensitive(false)
	re.entryPath.SetNoShowAll(false)
	re.entryPath.SetVisible(true)
	re.entryPath.SetText(r.Path)

	target := strings.Split(r.Target, ":")
	if len(target) != 2 {
		return
	}
	re.hostEntry.SetText(target[0])
	re.portEntry.SetText(target[1])

	if r.UID > -1 {
		re.comboUID.SetActiveID(strconv.FormatInt(int64(r.UID), 10))
	}
	if r.GID > -1 {
		re.comboGID.SetActiveID(strconv.FormatInt(int64(r.GID), 10))
	}

	if re.mode == DIALOG_MODE_EDIT {
		re.comboScope.SetVisible(false)
		re.comboScope.SetNoShowAll(true)
		re.comboScope.SetSensitive(false)
		re.labelScope.SetNoShowAll(false)
		re.labelScope.SetVisible(true)
		re.labelScope.SetText(strings.Title(strings.ToLower(sgfw.RuleModeString[sgfw.RuleMode(r.Mode)])))
	}
	if re.mode == DIALOG_MODE_PROMPT || r.Mode == uint16(sgfw.RULE_MODE_PROCESS) {
		re.titlePID.SetNoShowAll(false)
		re.titlePID.SetVisible(true)
		re.labelPID.SetNoShowAll(false)
		re.labelPID.SetVisible(true)
		pid := strconv.FormatUint(uint64(r.Pid), 10)
		re.labelPID.SetText(pid)
	}
	if re.mode == DIALOG_MODE_SAVEAS {
		re.comboScope.Remove(1)
		re.comboScope.SetSensitive(false)
	}
	if re.mode == DIALOG_MODE_PROMPT {
		re.entryOrigin.SetNoShowAll(false)
		re.entryOrigin.SetVisible(true)
		re.entryOrigin.SetSensitive(false)
		re.entryOrigin.SetText(r.Origin)
		re.labelOrigin.SetNoShowAll(false)
		re.labelOrigin.SetVisible(true)
		re.comboUID.SetSensitive(false)
		re.comboGID.SetSensitive(false)
		re.comboScope.SetActiveID(strconv.Itoa(int(sgfw.RuleModeValue[strings.ToUpper(re.row.rl.app.Config.DefaultAction)])))
		
		re.checkUID.SetNoShowAll(false)
		re.checkUID.SetVisible(true)
		re.checkUID.SetSensitive(true)
		re.checkGID.SetNoShowAll(false)
		re.checkGID.SetVisible(true)
		re.checkGID.SetSensitive(true)

		re.comboVerb.SetNoShowAll(true)
		re.comboVerb.SetVisible(false)
		re.comboVerb.SetSensitive(false)

		re.setPromptButtons()
		
		ctv := r.IsSocks
		if !ctv {
			re.checkTLS.SetSensitive(false)
			re.checkTLS.SetActive(false)
		}

	}

	if re.mode == DIALOG_MODE_INFO {
		re.comboScope.SetActiveID(strconv.Itoa(int(r.Mode)))
		re.comboScope.SetSensitive(false)
		re.comboVerb.SetSensitive(false)
		re.hostEntry.SetSensitive(false)
		re.portEntry.SetSensitive(false)
		re.comboUID.SetSensitive(false)
		re.comboGID.SetSensitive(false)
		re.checkUID.SetSensitive(false)
		re.checkGID.SetSensitive(false)
		re.comboProto.SetSensitive(false)
		re.checkTLS.SetSensitive(false)
		re.ok.SetNoShowAll(true)
		re.ok.SetSensitive(false)
		re.ok.SetVisible(false)
	}

	re.onProtoChanged()
}

func (re *ruleNew) setPromptButtons() {
	re.allow.SetNoShowAll(false)
	re.allow.SetVisible(true)
	re.allow.SetSensitive(true)
	re.ok.SetLabel("_Deny")
}

func (re *ruleNew) toggleCheckTLS(val bool) {
	if val && re.row.rule.IsSocks && re.mode != DIALOG_MODE_NEW  && re.mode != DIALOG_MODE_INFO {
		re.checkTLS.SetSensitive(true)
	} else {
		re.checkTLS.SetSensitive(false)
	}
}

func (re *ruleNew) onProtoChanged() {
	re.toggleCheckTLS( (re.comboProto.GetActiveID() == "tcp") )
	if re.comboProto.GetActiveID() == "icmp" {
		re.titlePort.SetText("Code:")
		re.portEntry.SetPlaceholderText("Code")
	} else {
		re.titlePort.SetText("Port:")
		re.portEntry.SetPlaceholderText("Port")
	}
	re.onChanged()
}

func (re *ruleNew) onVerbChanged() {
	re.toggleCheckTLS( (re.comboVerb.GetActiveID() == "allow") )
}

func (re *ruleNew) validateFields() bool {
	id := re.comboVerb.GetActiveID()
	if id != "allow" && id != "allow_tls" && id != "deny" {
		return false
	}
	proto := re.comboProto.GetActiveID()
	protos := []string{"", "tcp", "udp", "icmp"}
	found := false
	for _, p := range protos {
		if proto == p {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	host, _ := re.hostEntry.GetText()
	port, _ := re.portEntry.GetText()
	if !isValidHost(host) {
		return false
	}
	if !isValidPort(port, re.comboProto.GetActiveID()) {
		return false
	}
	if re.mode == DIALOG_MODE_NEW {
		fp := re.btnPathChooser.FileChooser.GetFilename()
		if fp == "" || !isExecutableFile(fp) {
			return false
		}
	}
	return true
}

func isExecutableFile(file string) bool {
	fi, _ := os.Stat(file)
	fm := fi.Mode()
	perm := uint32(fm.Perm())
	return !( (perm&UserExecute == 0) && (perm&GroupExecute == 0) && (perm&OtherExecute == 0) )
	
}

func (re *ruleNew) onPortInsertText(entry *gtk.Entry, text string) {
	current, _ := entry.GetText()
	if current == "" && text == "*" {
		return
	}
	if current == "*" {
		entry.StopEmission("insert-text")
		return
	}
	for _, c := range text {
		if !unicode.IsDigit(c) {
			entry.StopEmission("insert-text")
			return
		}
	}
}

func (re *ruleNew) onChanged() {
	valid := re.validateFields()
	re.ok.SetSensitive(valid)
	if re.mode == DIALOG_MODE_PROMPT {
		re.allow.SetSensitive(valid)
	}
}

func (re *ruleNew) onPathSet(btnChooser *gtk.FileChooserButton) {
	fp := btnChooser.FileChooser.GetFilename()
	if !isExecutableFile(fp) {
		warnDialog(&re.row.rl.app.win.Window, "%s", "File not an executable!")
	} else {
		btnChooser.SetTooltipText(fp)
	}
}

func (re *ruleNew) populateUID() {
	for _, id := range re.row.rl.app.userIDs {
		re.comboUID.Append(strconv.FormatInt(int64(id), 10), re.row.rl.app.userMap[id])
	}
}

func (re *ruleNew) populateGID() {
	for _, id := range re.row.rl.app.groupIDs {
		re.comboGID.Append(strconv.FormatInt(int64(id), 10), re.row.rl.app.groupMap[id])
	}
}
