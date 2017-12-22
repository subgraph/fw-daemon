// XXX: Clarify IsSocks, PID
// XXX: Leak on refresh
// XXX: Find way to share FirewallPrompt introspect xml with extension.js
// XXX: Prompt Only mode with different APPID (debug/dev)
// XXX? inotify refresh passwd/groups
// XXX: Existing prompt bugs:
// > XXX: Dead prompt requests not removed properly
// > XXX: Gtk-WARNING **: /build/gtk+3.0-NmdvYo/gtk+3.0-3.22.11/./gtk/gtktreestore.c:860: Unable to convert from gpointer to gchararray
package main

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/subgraph/fw-daemon/fw-settings/settings"
	"github.com/subgraph/fw-daemon/sgfw"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

type promptModes uint

const (
	promptModeDisabled promptModes = iota
	promptModeOnly
	promptModeEnabled
)

type switcherDirection uint

const (
	switcherDirectionUp switcherDirection = iota
	switcherDirectionDown
)

type appShortcuts struct {
	Accel string
	Group string
	Title string
}

type cbPromptAdd func(guid, path, icon, proto string, pid int, ipaddr, hostname string, port, uid, gid int,
	origin, timestamp string, is_socks bool, optstring string, sandbox string, action int) bool
type cbPromptRemove func(string)
var cbPromptAddRequest cbPromptAdd = nil
var cbPromptRemoveRequest cbPromptRemove = nil

const groupFile = "/etc/group"
const userFile = "/etc/passwd"

type fwApp struct {
	*gtk.Application

	forceMenu bool

	Dbus *dbusObject
	DbusServer *dbusServer

	promptMode promptModes
	prompt *Prompt

	Config *sgfw.FirewallConfigs
	Settings *settings.Settings

	winb *builder
	win *gtk.ApplicationWindow
	repopMutex *sync.Mutex

	swRulesPermanent *gtk.ScrolledWindow
	swRulesSession *gtk.ScrolledWindow
	swRulesProcess *gtk.ScrolledWindow
	swRulesSystem *gtk.ScrolledWindow
	swPrompt *gtk.ScrolledWindow

	boxPermanent *gtk.ListBox
	boxSession *gtk.ListBox
	boxProcess *gtk.ListBox
	boxSystem *gtk.ListBox

	rlPermanent *ruleList
	rlSession *ruleList
	rlProcess *ruleList
	rlSystem *ruleList

	btnNewRule *gtk.Button
	nbRules *gtk.Notebook
	tlStack *gtk.Stack
	tlStackSwitcher *gtk.StackSwitcher
	gridConfig *gtk.Grid
	entrySearch *gtk.SearchEntry
	btnSearch *gtk.ToggleButton
	revealerSearch *gtk.Revealer
	boxAppMenu *gtk.Box
	btnAppMenu *gtk.MenuButton
	dialog *gtk.MessageDialog

	signalDelete glib.SignalHandle

	lcache string
	shortcuts []appShortcuts

	userMap map[int32]string
	userIDs []int32
	groupMap map[int32]string
	groupIDs []int32
	userMapLock *sync.Mutex
	groupMapLock *sync.Mutex
	intcount uint

	ozProfiles []string
}


/*
 * App Setup
 */

func (fa *fwApp) init() {
	fa.Config = &sgfw.FirewallConfigs{}
	fa.repopMutex = &sync.Mutex{}

	fa.userMap = make(map[int32]string)
	fa.groupMap = make(map[int32]string)
	fa.userMapLock = &sync.Mutex{}
	fa.groupMapLock = &sync.Mutex{}

	fa.parseArgs()

	if err := fa.cacheUsers(); err != nil {
		panic(err)
	}

	if err := fa.cacheGroups(); err != nil {
		panic(err)
	}

	fa.initOZProfiles()

	fa.initGtk()
	fa.Settings = settings.Init()

	fa.Run(os.Args)
}

func (fa *fwApp) parseArgs() {
	fa.promptMode = promptModeEnabled
	for i := (len(os.Args) - 1); i > 0; i-- {
		k := strings.TrimLeft(os.Args[i], "-")
		found := false
		switch k {
		case "prompt-only":
			found = true
			fa.promptMode = promptModeOnly
		case "disable-prompt":
			found = true
			fa.promptMode = promptModeDisabled
		case "gapplication-force-menu":
			found = true
			fa.forceMenu = true
		}
		if found {
			os.Args = append(os.Args[:i], os.Args[(i+1):]...)
		}
	}
}

func (fa *fwApp) initGtk() {
	var appFlags glib.ApplicationFlags
	appFlags |= glib.APPLICATION_FLAGS_NONE
	appFlags |= glib.APPLICATION_CAN_OVERRIDE_APP_ID
	//appFlags |= glib.APPLICATION_IS_LAUNCHER
	//appFlags |= glib.APPLICATION_IS_SERVICE
	app, err := gtk.ApplicationNew("com.subgraph.Firewall.Settings", appFlags)//glib.APPLICATION_FLAGS_NONE)
	if err != nil {
		panic(fmt.Sprintf("gtk.ApplicationNew() failed: %v", err))
	}
	fa.Application = app

	fa.Connect("activate", fa.activate)
	fa.Connect("startup", fa.startup)
}

func (fa *fwApp) activate(app *gtk.Application) {
	win := fa.GetActiveWindow()
	if win != nil {
		win.Present()
		return
	}

	fa.build()
	fa.populateWindow()
	fa.registerActions()
	fa.registerShortcuts()
	fa.AddWindow(&fa.win.Window)
	fa.win.ShowAll()
}

func (fa *fwApp) startup() {
	dbus, err := newDbusObject()
	if err != nil {
		failDialog(&fa.win.Window, "Failed to connect to dbus system bus: %v", err)
	}
	fa.Dbus = dbus

	if fa.promptMode != promptModeDisabled {
		dbuss, _ := newPromptDbusServer()
		if fa.promptMode == promptModeOnly && dbuss == nil {
			fmt.Println("Prompter already available exiting...")
			os.Exit(0)
		}
		fa.DbusServer = dbuss
		if fa.DbusServer == nil {
			fa.promptMode = promptModeDisabled
		}
	}

	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT)
	go fa.handleSignals(sigs)

	go dbusSignalHandler(fa)
}

func (fa *fwApp) build() {
	fa.buildWindow()
	fa.buildAppMenu()
}

func (fa *fwApp) registerActions() {
	anr := glib.SimpleActionNew("new_rule", glib.VARIANT_TYPE_NONE)
	anr.Connect("activate", func () {
		fa.btnNewRule.Activate()
	})
	fa.ActionMap.AddAction(&anr.Action)

	snr := glib.SimpleActionNew("shortcuts", glib.VARIANT_TYPE_NONE)
	snr.Connect("activate", func () {
		fa.showShortcutsWindow()
	})
	fa.ActionMap.AddAction(&snr.Action)

	abnr := glib.SimpleActionNew("about", glib.VARIANT_TYPE_NONE)
	abnr.Connect("activate", func() {fa.showAboutDialog()})
	fa.ActionMap.AddAction(&abnr.Action)
/*
	hbnr := glib.SimpleActionNew("help", glib.VARIANT_TYPE_NONE)
	hbnr.Connect("activate", func() {fmt.Println("UNIMPLEMENTED")})
	fa.ActionMap.AddAction(&hbnr.Action)
*/
	qnr := glib.SimpleActionNew("quit", glib.VARIANT_TYPE_NONE)
	qnr.Connect("activate", func() {
		fa.win.Close()
	})
	fa.ActionMap.AddAction(&qnr.Action)
}

func (fa *fwApp) registerShortcuts() {
	fa.ConnectShortcut("<Primary><Alt>Page_Down", "rules", "Go to next rules views", fa.win.Window, func (win gtk.Window) {
		fa.switchRulesItem(switcherDirectionUp)
	})
	fa.ConnectShortcut("<Primary><Alt>Page_Up", "rules", "Go to previous rules views", fa.win.Window, func (win gtk.Window) {
		fa.switchRulesItem(switcherDirectionDown)
	})
	fa.ConnectShortcut("<Primary>n", "rules", "Create new rule", fa.win.Window, func (win gtk.Window) {
		if fa.btnNewRule.GetSensitive() {
			fa.btnNewRule.Emit("clicked")
		}
	})
	fa.ConnectShortcut("<Primary>f", "rules", "Search for rule", fa.win.Window, func (win gtk.Window) {
		if fa.tlStack.GetVisibleChildName() == "rules" {
			reveal := fa.revealerSearch.GetRevealChild()
			if !reveal {
				fa.btnSearch.SetActive(true)
				fa.revealerSearch.SetRevealChild(true)
			}
			fa.entrySearch.Widget.GrabFocus()
		}
	})
	fa.ConnectShortcut("<Primary><Shift>Page_Down", "general", "Go to the next view", fa.win.Window, func (win gtk.Window) {
		fa.switchStackItem(switcherDirectionDown)
	})
	fa.ConnectShortcut("<Primary><Shift>Page_Up", "general", "Go to the previous view", fa.win.Window, func (win gtk.Window) {
		fa.switchStackItem(switcherDirectionUp)
	})
	if fa.promptMode != promptModeDisabled {
		fa.RegisterShortcutHelp("<Primary><Alt>space", "general", "Answer first firewall prompt")
	}
/*
	fa.ConnectShortcut("<Primary>question", "general", "Show the program help", fa.win.Window, func (win gtk.Window) {
		ha := fa.ActionMap.LookupAction("help")
		if ha != nil {
			ha.Activate(nil)
		}
	})
*/
	fa.ConnectShortcut("F1", "general", "Show this help window", fa.win.Window, func (win gtk.Window) {
		fa.showShortcutsWindow()
	})
	fa.ConnectShortcut("<Primary>q", "general", "Exit program", fa.win.Window, func (win gtk.Window) {
		fa.win.Close()
	})
	// Easter Egg
	fa.ConnectShortcut("<Primary>F5", "", "", fa.win.Window, func (win gtk.Window) {
		fa.repopulateWindow()
		fa.loadConfig(false)
	})
}

func (fa *fwApp) buildWindow() {
	fa.winb = newBuilder("Dialog")
	fa.winb.getItems(
		"window", &fa.win,
		"swRulesPermanent", &fa.swRulesPermanent,
		"swRulesSession", &fa.swRulesSession,
		"swRulesProcess", &fa.swRulesProcess,
		"swRulesSystem", &fa.swRulesSystem,
		"btn_new_rule", &fa.btnNewRule,
		"rulesnotebook", &fa.nbRules,
		"toplevel_stack", &fa.tlStack,
		"config_grid", &fa.gridConfig,
		"stack_switcher", &fa.tlStackSwitcher,
		"prompt_scrollwindow", &fa.swPrompt,
		"search_entry", &fa.entrySearch,
		"btn_search", &fa.btnSearch,
		"search_revealer", &fa.revealerSearch,
		"box_app_menu", &fa.boxAppMenu,
		"btn_app_menu", &fa.btnAppMenu,
	)

	fa.win.SetIconName("security-medium")
	fa.win.SetTitle("Subgraph Firewall Settings")
/*
	fa.winb.ConnectSignals(map[string]interface{} {
		"on_changed_search": fa.onChangedSearch,
		"on_stoped_search":  fa.onStopedSearch,
	})
*/
	//fa.swRulesPermanent.Connect("key-press-event", fa.onRulesKeyPress)
	fa.entrySearch.Connect("search-changed", fa.onChangedSearch)
	fa.entrySearch.Connect("stop-search", fa.onStopedSearch)
	fa.btnSearch.Connect("clicked", fa.onButtonSearchClicked)

	fa.btnNewRule.Connect("clicked", fa.showAddRuleDialog)
	fa.tlStackSwitcher.Connect("event", fa.onStackChanged)

	fa.win.Connect("configure-event", fa.onWindowConfigure)

	fa.signalDelete, _ = fa.win.Connect("delete-event", fa.onWindowDelete)

	fa.win.SetPosition(gtk.WIN_POS_CENTER)

	if fa.Settings.GetWindowHeight() > 0 && fa.Settings.GetWindowWidth() > 0 {
		fa.win.Resize(int(fa.Settings.GetWindowWidth()), int(fa.Settings.GetWindowHeight()))
	}

	if fa.Settings.GetWindowTop() > 0 && fa.Settings.GetWindowLeft() > 0 {
		fa.win.Move(int(fa.Settings.GetWindowLeft()), int(fa.Settings.GetWindowTop()))
	}

	fa.loadConfig(true)

	if fa.promptMode != promptModeDisabled {
		fa.tlStack.SetVisibleChildName("prompt")
		prompt, err := createPromptView(fa, fa.swPrompt)
		if err != nil {
			fmt.Println("Unable to create prompter:", err)
			os.Exit(1)
		}
		fa.prompt = prompt
		cbPromptAddRequest = fa.prompt.AddRequest
		cbPromptRemoveRequest = fa.prompt.RemoveRequest
		if fa.promptMode == promptModeOnly {
			fa.win.Iconify()
		}
	} else {
		fa.tlStack.SetVisibleChildName("rules")
		fa.swPrompt.Destroy()
	}
}

func (fa *fwApp) buildAppMenu() {
	ap := glib.MenuNew()
	ams := glib.MenuNew()

	ap.Append("_New Rule...", "app.new_rule")

	ams.Append("_Keyboard Shortcuts", "app.shortcuts")
	//ams.Append("_Help", "app.help")
	ams.Append("_About", "app.about")
	ams.Append("_Quit", "app.quit")
	ap.AppendSection("", &ams.MenuModel)

	if !fa.forceMenu {
		fa.SetAppMenu(&ap.MenuModel)
	}

	if fa.forceMenu || !fa.PrefersAppMenu() {
		fa.boxAppMenu.SetNoShowAll(false)
		fa.boxAppMenu.SetVisible(true)
		fa.btnAppMenu.SetMenuModel(&ap.MenuModel)
	}
}


/*
 * Windows
 */

func (fa *fwApp) showPromptQuit() bool {
	fa.win.SetUrgencyHint(true)
	fa.win.Deiconify()
	fa.win.SetKeepAbove(true)

	res := false
	body := "Currently running as the prompt, are you sure you want to exit?"
	msg := "The Firewall will stop working as expected!"
	fa.dialog = gtk.MessageDialogNewWithMarkup(
		fa.win,
		gtk.DIALOG_DESTROY_WITH_PARENT,
		gtk.MESSAGE_WARNING,
		gtk.BUTTONS_OK_CANCEL,
		"")
	fa.dialog.SetMarkup(body)
	fa.dialog.SetProperty("secondary-text", msg)
	if fa.dialog.Run() == (int)(gtk.RESPONSE_OK) {
		res = true
	} else {
		fa.intcount = 0
		fa.win.SetUrgencyHint(false)
		fa.win.SetKeepAbove(false)
	}
	fa.dialog.Destroy()
	return res
}

func (fa *fwApp) showAddRuleDialog() {
	rule := &sgfw.DbusRule{}
	rl := &ruleList{app: fa}
	rr := &ruleRow{ rl: rl, rule: rule}
	rnew := newRuleAdd(rr, DIALOG_MODE_NEW)
	rnew.update()
	rnew.run("", nil)
}

func (fa *fwApp) showAboutDialog() {
	url := "https://subgraph.com/sgos/"
	sfs := "Subgraph Firewall"
	t := time.Now()
	cs := fmt.Sprintf("%d Subgraph Inc", t.Year())

	license := "BSD3"
	lf := "/usr/share/common-licenses/BSD"
	if fa.lcache != "" {
		license = license + "\n\n" + fa.lcache
	} else {
		if _, err := os.Stat(lf); err == nil {
			bb, err := ioutil.ReadFile(lf)
			if err == nil {
				fa.lcache = string(bb)
				fa.lcache = strings.Replace(fa.lcache, "The Regents of the University of California", cs, -1)
				license = license + "\n\n" + fa.lcache
			}
		}
	}

	ad, _ := gtk.AboutDialogNew()
	ad.SetName(sfs)
	ad.SetProgramName(sfs)
	ad.SetAuthors([]string{"<a href=\""+url+"\">Subgraph Inc</a>"})
	//ad.AddCreditSection("", []string{"- Bruce Leidl", "- David Mirza", "- Stephen Watt", "- Matthieu Lalonde"})
	ad.SetVersion("0.1.0")
	ad.SetCopyright(fmt.Sprintf("© %s.", cs))
	ad.SetComments("An interface for the " + sfs)
	ad.SetWebsite(url)
	ad.SetWebsiteLabel(url)
	ad.SetLogoIconName("security-medium")
	ad.SetWrapLicense(true)
	ad.SetLicenseType(gtk.LICENSE_BSD)
	ad.SetLicense(license)
	ad.SetWrapLicense(true)

	ad.SetTransientFor(&fa.win.Window)
	ad.Run()
	ad.Destroy()
}

func (fa *fwApp) showShortcutsWindow() {
	var groups = []string{"general", "rules", "prompt"}
	var titles = map[string]string{
		"general": "General",
		"rules": "Rules",
		"prompt": "Firewall Prompt",
	}
	xv := new(GtkXMLInterface)
	xv.Comment = " interface-requires gtk+ 3.20 "
	xv.Requires = &GtkXMLRequires{Lib: "gtk+", Version: "3.20"}
	xsw := new(GtkXMLObject)
	xsw.Class = "GtkShortcutsWindow"
	xsw.ID = "shortcuts_window"
	xsw.Properties = []GtkXMLProperty{
		{Name: "modal", Value: "1"},
		{Name: "visible", Value: "1"},
	}
	xss := new(GtkXMLObject)
	xss.Class = "GtkShortcutsSection"
	xss.Properties = []GtkXMLProperty{
			{Name: "visible", Value: "1"},
			{Name: "section-name", Value: "shortcuts"},
			{Name: "max-height", Value: "16"},
		}
	xsw.Children = append(xsw.Children, GtkXMLChild{Objects: []*GtkXMLObject{xss}})

	for _, g := range groups {
		xsg := new(GtkXMLObject)
		xsg.Class = "GtkShortcutsGroup"
		xsg.Properties = []GtkXMLProperty{
				{Name: "title", Value: titles[g], Translatable: "yes"},
				{Name: "visible", Value: "1"},
			}
		found := false
		for _, sc := range fa.shortcuts {
			if sc.Group != g {
				continue
			}
			found = true
			xps := new(GtkXMLObject)
			xps.Class = "GtkShortcutsShortcut"
			xps.Properties = []GtkXMLProperty{
					{Name: "visible", Value: "yes"},
					{Name: "accelerator", Value: sc.Accel},
					{Name: "title", Translatable: "yes", Value: sc.Title},
				}
			xsg.Children = append(xsg.Children, GtkXMLChild{Objects: []*GtkXMLObject{xps}})
		}
		if found {
			xss.Children = append(xss.Children, GtkXMLChild{Objects: []*GtkXMLObject{xsg}})
		}
	}

	xv.Objects = append(xv.Objects, xsw)
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	enc := xml.NewEncoder(writer)
	enc.Indent("", "	")
	if err := enc.Encode(xv); err != nil {
		fmt.Printf("XML ERROR: %+v\n", err)
	} else {
		//fmt.Println(xml.Header + buf.String())
		var sw *gtk.ShortcutsWindow
		b := newBuilderFromString(xml.Header + buf.String())
		b.getItems(
			"shortcuts_window", &sw,
		)
		sw.Window.SetTransientFor(&fa.win.Window)
		sw.Window.SetPosition(gtk.WIN_POS_CENTER_ON_PARENT)
		sw.Window.SetModal(true)
		fa.AddWindow(&sw.Window)
		//sw.ShowAll()
		sw.Present()
	}
}


/*
 * Private Utils
 */

func (fa *fwApp) populateWindow() {
	tt, _ := fa.entrySearch.GetText()
	if fa.boxPermanent == nil {
		fa.boxPermanent, _ = gtk.ListBoxNew()
		fa.swRulesPermanent.Add(fa.boxPermanent)
			
		fa.rlPermanent = newRuleList(fa, fa.boxPermanent, sgfw.RULE_MODE_PERMANENT)
		if _, err := fa.Dbus.isEnabled(); err != nil {
			failDialog(&fa.win.Window, "Unable is connect to firewall daemon.  Is it running?")
		}
	}
	fa.rlPermanent.loadRules(true)
	fa.rlPermanent.reloadRules(tt)


	if fa.boxSession == nil {
		fa.boxSession, _ = gtk.ListBoxNew()
		fa.swRulesSession.Add(fa.boxSession)

		fa.rlSession = newRuleList(fa, fa.boxSession, sgfw.RULE_MODE_SESSION)
		if _, err := fa.Dbus.isEnabled(); err != nil {
			failDialog(&fa.win.Window, "Unable is connect to firewall daemon.  Is it running?")
		}
	}
	fa.rlSession.loadRules(true)
	fa.rlSession.reloadRules(tt)


	if fa.boxProcess == nil {
		fa.boxProcess, _ = gtk.ListBoxNew()
		fa.swRulesProcess.Add(fa.boxProcess)

		fa.rlProcess = newRuleList(fa, fa.boxProcess, sgfw.RULE_MODE_PROCESS)
		if _, err := fa.Dbus.isEnabled(); err != nil {
			failDialog(&fa.win.Window, "Unable is connect to firewall daemon.  Is it running?")
		}
	}
	fa.rlProcess.loadRules(true)
	fa.rlProcess.reloadRules(tt)

	if fa.boxSystem == nil {
		fa.boxSystem, _ = gtk.ListBoxNew()
		fa.swRulesSystem.Add(fa.boxSystem)
		
		fa.rlSystem = newRuleList(fa, fa.boxSystem, sgfw.RULE_MODE_SYSTEM)
		if _, err := fa.Dbus.isEnabled(); err != nil {
			failDialog(&fa.win.Window, "Unable is connect to firewall daemon.  Is it running?")
		}
	}
	fa.rlSystem.loadRules(true)
	fa.rlSystem.reloadRules(tt)


}

func (fa *fwApp) repopulateWindow() {
	fmt.Println("Refreshing firewall rule list.")
	fa.repopMutex.Lock()
	defer fa.repopMutex.Unlock()
/*
	child, err := fa.swRulesPermanent.GetChild()
	if err != nil {
		failDialog(&fa.win.Window, "Unable to clear out permanent rules list display: %v", err)
	}
	fa.swRulesPermanent.Remove(child)

	child, err = fa.swRulesSession.GetChild()
	if err != nil {
		failDialog(&fa.win.Window, "Unable to clear out session rules list display: %v", err)
	}
	fa.swRulesSession.Remove(child)

	child, err = fa.swRulesProcess.GetChild()
	if err != nil {
		failDialog(&fa.win.Window, "Unable to clear out process rules list display: %v", err)
	}
	fa.swRulesProcess.Remove(child)

	child, err = fa.swRulesSystem.GetChild()
	if err != nil {
		failDialog(&fa.win.Window, "Unable to clear out system rules list display: %v", err)
	}
	fa.swRulesSystem.Remove(child)
*/
	if fa.tlStack.GetVisibleChildName() != "rules" && fa.promptMode == promptModeDisabled {
		stack := fa.tlStack.GetChildByName("rules")
		err := fa.tlStack.ChildSetProperty(stack, "needs-attention", true)
		if err != nil {
			fmt.Println("Error setting stack attention")
		}
	}

	fa.populateWindow()
	fa.win.ShowAll()
}

func (fa *fwApp) switchRulesItem(dir switcherDirection) {
	focus := (fa.nbRules.Container.GetFocusChild() != nil || fa.nbRules.HasFocus())
	if focus {
		return
	}
	if fa.tlStack.GetVisibleChildName() != "rules" {
		return
	}
	if dir == switcherDirectionUp {
		if fa.nbRules.GetNPages() == (fa.nbRules.GetCurrentPage() + 1) {
			fa.nbRules.SetCurrentPage(0)
		} else {
			fa.nbRules.NextPage()
		}
	} else {
		if fa.nbRules.GetCurrentPage() == 0 {
			fa.nbRules.SetCurrentPage(fa.nbRules.GetNPages() - 1)
		} else {
			fa.nbRules.PrevPage()
		}
	}
}

func (fa *fwApp) switchStackItem(dir switcherDirection) {
	stacks := []string{"prompt", "rules", "config"}
	stacksByName := map[string]int{
		"prompt": 0,
		"rules": 1,
		"config": 2,
	}
	if fa.promptMode == promptModeDisabled {
		stacks = stacks[1:]
		delete(stacksByName, "prompt")
		stacksByName["rules"] = 0
		stacksByName["config"] = 1
	}
	idx := stacksByName[fa.tlStack.GetVisibleChildName()]
	if dir == switcherDirectionUp {
		idx = idx - 1
		if idx < 0 {
			idx = len(stacks) - 1
		}
		fa.tlStack.SetVisibleChildFull(stacks[idx], gtk.STACK_TRANSITION_TYPE_SLIDE_LEFT_RIGHT)
	} else {
		idx = idx + 1
		if idx >= len(stacks) {
			idx = 0
		}
		fa.tlStack.SetVisibleChildFull(stacks[idx], gtk.STACK_TRANSITION_TYPE_SLIDE_LEFT_RIGHT)
	}
	fa.onStackChanged()
}


/*
 * Handlers
 */

func (fa *fwApp) handleSignals(c <-chan os.Signal) {
	for {
		sig := <-c
		switch sig {
		case syscall.SIGINT:
			if fa.intcount == 0 {
				glib.IdleAdd(func () bool {
					fa.win.Close()
					return false
				})
			} else {
				if fa.signalDelete != 0 {
					fa.win.HandlerDisconnect(fa.signalDelete)
				}
				fa.win.Destroy()
			}
			fa.intcount++
		}
	}
}

func (fa *fwApp) handleRefreshRules() {
	fa.repopulateWindow()
}

func (fa *fwApp) handleRefreshConfig() {
	fa.loadConfig(false)
}

func (fa *fwApp) onWindowConfigure() {
	w, h := fa.win.GetSize()
	fa.Settings.SetWindowHeight(uint(h))
	fa.Settings.SetWindowWidth(uint(w))
	l, t := fa.win.GetPosition()
	fa.Settings.SetWindowTop(uint(t))
	fa.Settings.SetWindowLeft(uint(l))
}

func (fa *fwApp) onWindowDelete() bool {
	if fa.promptMode != promptModeDisabled {
		if !fa.showPromptQuit() {
			return true
		}
	}
	return false
}

func (fa *fwApp) onStackChanged() {
tn := fa.tlStack.GetVisibleChildName()
	nra := fa.ActionMap.LookupAction("new_rule")
	if tn == "rules" {
		fa.btnNewRule.SetSensitive(true)
		nra.SetProperty("enabled", true)
		stack := fa.tlStack.GetChildByName("rules")
		err := fa.tlStack.ChildSetProperty(stack, "needs-attention", false)
		if err != nil {
			fmt.Println("Error unsetting stack attention")
		}
	} else if tn == "prompt" {
		fa.btnNewRule.SetSensitive(true)
		nra.SetProperty("enabled", true)
		stack := fa.tlStack.GetChildByName("prompt")
		err := fa.tlStack.ChildSetProperty(stack, "needs-attention", false)
		if err != nil {
			fmt.Println("Error unsetting stack attention")
		}
	} else {
		fa.btnNewRule.SetSensitive(false)
		nra.SetProperty("enabled", false)
	}

	if fa.prompt != nil && tn != "prompt"{
		pstack := fa.tlStack.GetChildByName("prompt")
		nag, _ := fa.tlStack.ChildGetProperty(pstack, "needs-attention", glib.TYPE_BOOLEAN)
		if fa.prompt.HasItems() && !nag.(bool) {
			err := fa.tlStack.ChildSetProperty(pstack, "needs-attention", true)
			if err != nil {
				fmt.Println("Error unsetting stack attention")
			}
		}
	}
}

func (fa *fwApp) onChangedSearch(entry *gtk.SearchEntry) {
	fa.repopMutex.Lock()
	defer fa.repopMutex.Unlock()
	tt, _ := entry.Entry.GetText()
	fa.rlPermanent.reloadRules(tt)
	fa.rlSession.reloadRules(tt)
	fa.rlProcess.reloadRules(tt)
	fa.rlSystem.reloadRules(tt)
}

func (fa *fwApp) onStopedSearch() {
	fa.entrySearch.Entry.SetText("")
	fa.btnSearch.SetActive(false)
	fa.revealerSearch.SetRevealChild(false)
}

func (fa *fwApp) onButtonSearchClicked() {
	reveal := fa.revealerSearch.GetRevealChild()
	if reveal {
		fa.entrySearch.SetText("")
	}
	fa.btnSearch.SetActive(!reveal)
	fa.revealerSearch.SetRevealChild(!reveal)
	fa.entrySearch.Widget.GrabFocus()
}

func (fa *fwApp) onRulesKeyPress(i interface{}, e *gdk.Event) bool {
	ek := gdk.EventKeyNewFromEvent(e)
	reveal := fa.revealerSearch.GetRevealChild()
	if !reveal {
		fa.btnSearch.SetActive(true)
		fa.revealerSearch.SetRevealChild(true)
	}
	fa.entrySearch.GrabFocusWithoutSelecting()
	fa.entrySearch.SetText(string(ek.KeyVal()))
	return true
}


/*
 * Users, Groups
 */

func (fa *fwApp) cacheUsers() error {
	f, err := os.Open(userFile)
	if err != nil {
		return err
	}
	defer f.Close()
	fa.userMapLock.Lock()
	defer fa.userMapLock.Unlock()

	readColonFile(f, func (line []byte) {
		t := strings.Split(string(line), ":")
		id, _ := strconv.ParseInt(t[2], 10, 32)
		fa.userMap[int32(id)] = t[0]
		fa.userIDs = append(fa.userIDs, int32(id))
	})
	return nil

}

func (fa *fwApp) cacheGroups() error {
	f, err := os.Open(groupFile)
	if err != nil {
		return err
	}
	defer f.Close()
	fa.groupMapLock.Lock()
	defer fa.groupMapLock.Unlock()

	readColonFile(f, func (line []byte) {
		t := strings.Split(string(line), ":")
		id, _ := strconv.ParseInt(t[2], 10, 32)
		fa.groupMap[int32(id)] = t[0]
		fa.groupIDs = append(fa.groupIDs, int32(id))
	})
	return nil
}


/*
 * Exported
 */

func (fa *fwApp) RegisterShortcutHelp(accel, group, title string) {
	fa.shortcuts = append(fa.shortcuts, appShortcuts{Accel: accel, Group: group, Title: title})
}

func (fa *fwApp) ConnectShortcut(accel, group, title string, w gtk.Window, action func(gtk.Window)) {
	if group != "" && title != "" {
		fa.RegisterShortcutHelp(accel, group, title)
	}
	gr, _ := gtk.AccelGroupNew()
	key, mod := gtk.AcceleratorParse(accel)

	// Do not remove the closure here - there is a limitation
	// in gtk that makes it necessary to have different functions for different accelerator groups
	gr.Connect(key, mod, gtk.ACCEL_VISIBLE, func() {
		action(w)
	})

	w.AddAccelGroup(gr)
	w.Connect("delete-event", func () bool {
		w.RemoveAccelGroup(gr)
		return false
	})
}

func (fa *fwApp) LookupUsername(uid int32) string {
	if uid == -1 {
		return "any"
	}
	fa.userMapLock.Lock()
	defer fa.userMapLock.Unlock()

	if val, ok := fa.userMap[uid]; ok {
		return val
	}
	return "unknown"
}

func (fa *fwApp) LookupGroup(gid int32) string {
	if gid == -1 {
		return "any"
	}
	fa.groupMapLock.Lock()
	defer fa.groupMapLock.Unlock()

	if val, ok := fa.groupMap[gid]; ok {
		return val
	}
	return "unknown"
}


/*
 * Global Utils
 */

func failDialog(parent *gtk.Window, format string, args ...interface{}) {
	d := gtk.MessageDialogNew(parent, 0, gtk.MESSAGE_ERROR, gtk.BUTTONS_CLOSE,
		format, args...)
	d.Run()
	os.Exit(1)
}

func warnDialog(parent *gtk.Window, format string, args ...interface{}) {
	d := gtk.MessageDialogNew(parent, 0, gtk.MESSAGE_WARNING, gtk.BUTTONS_CLOSE,
		format, args...)
	d.Run()
	d.Destroy()
}

// readColonFile parses r as an /etc/group or /etc/passwd style file, running
// fn for each row. readColonFile returns a value, an error, or (nil, nil) if
// the end of the file is reached without a match.
func readColonFile(r io.Reader, fn func(line []byte)) (v interface{}, err error) {
	bs := bufio.NewScanner(r)
	for bs.Scan() {
		line := bs.Bytes()
		// There's no spec for /etc/passwd or /etc/group, but we try to follow
		// the same rules as the glibc parser, which allows comments and blank
		// space at the beginning of a line.
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		fn(line)
	}
	return nil, bs.Err()
}


/*
 * Main
 */

func main() {
	app := &fwApp{}
	app.init()
}
