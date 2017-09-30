package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/subgraph/fw-daemon/sgfw"
)

type fpPreferences struct {
	Winheight uint
	Winwidth  uint
	Wintop    uint
	Winleft   uint
}

type ruleColumns struct {
	nrefs     int
	Path      string
	GUID      string
	Icon      string
	Proto     string
	Pid       int
	Target    string
	Hostname  string
	Port      int
	UID       int
	GID       int
	Uname     string
	Gname     string
	Origin    string
	Timestamp string
	IsSocks   bool
	ForceTLS  bool
	Scope     int
}

const (
	COL_NO_NREFS = iota
	COL_NO_ICON_PIXBUF
	COL_NO_GUID
	COL_NO_PATH
	COL_NO_ICON
	COL_NO_PROTO
	COL_NO_PID
	COL_NO_DSTIP
	COL_NO_HOSTNAME
	COL_NO_PORT
	COL_NO_UID
	COL_NO_GID
	COL_NO_ORIGIN
	COL_NO_TIMESTAMP
	COL_NO_IS_SOCKS
	COL_NO_OPTSTRING
	COL_NO_ACTION
	COL_NO_LAST
)

var dbuso *dbusObject
var userPrefs fpPreferences
var mainWin *gtk.Window
var Notebook *gtk.Notebook
var globalTS *gtk.TreeStore = nil
var globalTV *gtk.TreeView
var globalPromptLock = &sync.Mutex{}
var recentLock = &sync.Mutex{}
var globalIcon *gtk.Image

var editApp, editTarget, editPort, editUser, editGroup *gtk.Entry
var comboProto *gtk.ComboBoxText
var radioOnce, radioProcess, radioParent, radioSession, radioPermanent *gtk.RadioButton
var btnApprove, btnDeny, btnIgnore *gtk.Button
var chkTLS, chkUser, chkGroup *gtk.CheckButton
var recentlyRemoved = []string{}

func wasRecentlyRemoved(guid string) bool {
	recentLock.Lock()
	defer recentLock.Unlock()

	for gind, g := range recentlyRemoved {
		if g == guid {
			recentlyRemoved = append(recentlyRemoved[:gind], recentlyRemoved[gind+1:]...)
			return true
		}
	}

	return false
}

func addRecentlyRemoved(guid string) {
	recentLock.Lock()
	defer recentLock.Unlock()
	fmt.Println("RECENTLY REMOVED: ", guid)
	recentlyRemoved = append(recentlyRemoved, guid)
}

func promptInfo(msg string) {
	dialog := gtk.MessageDialogNew(mainWin, 0, gtk.MESSAGE_INFO, gtk.BUTTONS_OK, "Displaying full log info:")
	//	dialog.SetDefaultGeometry(500, 200)

	tv, err := gtk.TextViewNew()

	if err != nil {
		log.Fatal("Unable to create TextView:", err)
	}

	tvbuf, err := tv.GetBuffer()

	if err != nil {
		log.Fatal("Unable to get buffer:", err)
	}

	tvbuf.SetText(msg)
	tv.SetEditable(false)
	tv.SetWrapMode(gtk.WRAP_WORD)

	scrollbox, err := gtk.ScrolledWindowNew(nil, nil)

	if err != nil {
		log.Fatal("Unable to create scrolled window:", err)
	}

	scrollbox.Add(tv)
	scrollbox.SetSizeRequest(500, 100)

	box, err := dialog.GetContentArea()

	if err != nil {
		log.Fatal("Unable to get content area of dialog:", err)
	}

	box.Add(scrollbox)
	dialog.ShowAll()
	dialog.Run()
	dialog.Destroy()
	//self.set_default_size(150, 100)
}

func promptChoice(msg string) int {
	dialog := gtk.MessageDialogNew(mainWin, 0, gtk.MESSAGE_ERROR, gtk.BUTTONS_YES_NO, msg)
	result := dialog.Run()
	dialog.Destroy()
	return result
}

func promptError(msg string) {
	dialog := gtk.MessageDialogNew(mainWin, 0, gtk.MESSAGE_ERROR, gtk.BUTTONS_CLOSE, "Error: %s", msg)
	dialog.Run()
	dialog.Destroy()
}

func getConfigPath() string {
	usr, err := user.Current()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not determine location of user preferences file:", err, "\n")
		return ""
	}

	prefPath := usr.HomeDir + "/.fwprompt.json"
	return prefPath
}

func savePreferences() bool {
	usr, err := user.Current()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not determine location of user preferences file:", err, "\n")
		return false
	}

	prefPath := usr.HomeDir + "/.fwprompt.json"

	jsonPrefs, err := json.Marshal(userPrefs)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not generate user preferences data:", err, "\n")
		return false
	}

	err = ioutil.WriteFile(prefPath, jsonPrefs, 0644)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not save user preferences data:", err, "\n")
		return false
	}

	return true
}

func loadPreferences() bool {
	usr, err := user.Current()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not determine location of user preferences file: %v", err, "\n")
		return false
	}

	prefPath := usr.HomeDir + "/.fwprompt.json"

	jfile, err := ioutil.ReadFile(prefPath)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not read preference data from file: %v", err, "\n")
		return false
	}

	err = json.Unmarshal(jfile, &userPrefs)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not load preferences data from file: %v", err, "\n")
		return false
	}

	fmt.Println(userPrefs)
	return true
}

func get_hbox() *gtk.Box {
	hbox, err := gtk.BoxNew(gtk.ORIENTATION_HORIZONTAL, 0)

	if err != nil {
		log.Fatal("Unable to create horizontal box:", err)
	}

	return hbox
}

func get_vbox() *gtk.Box {
	vbox, err := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 0)

	if err != nil {
		log.Fatal("Unable to create vertical box:", err)
	}

	return vbox
}

func get_checkbox(text string, activated bool) *gtk.CheckButton {
	cb, err := gtk.CheckButtonNewWithLabel(text)

	if err != nil {
		log.Fatal("Unable to create new checkbox:", err)
	}

	cb.SetActive(activated)
	return cb
}

func get_combobox() *gtk.ComboBoxText {
	combo, err := gtk.ComboBoxTextNew()

	if err != nil {
		log.Fatal("Unable to create combo box:", err)
	}

	combo.Append("tcp", "TCP")
	combo.Append("udp", "UDP")
	combo.Append("icmp", "ICMP")
	combo.SetActive(0)
	return combo
}

func get_radiobutton(group *gtk.RadioButton, label string, activated bool) *gtk.RadioButton {

	if group == nil {
		radiobutton, err := gtk.RadioButtonNewWithLabel(nil, label)

		if err != nil {
			log.Fatal("Unable to create radio button:", err)
		}

		radiobutton.SetActive(activated)
		return radiobutton
	}

	radiobutton, err := gtk.RadioButtonNewWithLabelFromWidget(group, label)

	if err != nil {
		log.Fatal("Unable to create radio button in group:", err)
	}

	radiobutton.SetActive(activated)
	return radiobutton
}

func get_entry(text string) *gtk.Entry {
	entry, err := gtk.EntryNew()

	if err != nil {
		log.Fatal("Unable to create text entry:", err)
	}

	entry.SetText(text)
	return entry
}

func get_label(text string) *gtk.Label {
	label, err := gtk.LabelNew(text)

	if err != nil {
		log.Fatal("Unable to create label in GUI:", err)
		return nil
	}

	return label
}

func createColumnImg(title string, id int) *gtk.TreeViewColumn {
	cellRenderer, err := gtk.CellRendererPixbufNew()
	if err != nil {
		log.Fatal("Unable to create image cell renderer:", err)
	}

	column, err := gtk.TreeViewColumnNewWithAttribute(title, cellRenderer, "pixbuf", id)
	if err != nil {
		log.Fatal("Unable to create cell column:", err)
	}

	return column
}

func createColumnText(title string, id int) *gtk.TreeViewColumn {
	cellRenderer, err := gtk.CellRendererTextNew()
	if err != nil {
		log.Fatal("Unable to create text cell renderer:", err)
	}

	column, err := gtk.TreeViewColumnNewWithAttribute(title, cellRenderer, "text", id)
	if err != nil {
		log.Fatal("Unable to create cell column:", err)
	}

	column.SetSortColumnID(id)
	column.SetResizable(true)
	return column
}

func createTreeStore(general bool) *gtk.TreeStore {
	colData := []glib.Type{glib.TYPE_INT, glib.TYPE_OBJECT, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_INT, glib.TYPE_STRING,
		glib.TYPE_STRING, glib.TYPE_INT, glib.TYPE_INT, glib.TYPE_INT, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_INT, glib.TYPE_STRING, glib.TYPE_INT}

	treeStore, err := gtk.TreeStoreNew(colData...)
	if err != nil {
		log.Fatal("Unable to create list store:", err)
	}

	return treeStore
}

func removeRequest(treeStore *gtk.TreeStore, guid string) {
	if wasRecentlyRemoved(guid) {
		fmt.Printf("Entry for %s was recently removed; deleting from cache\n", guid)
		return
	}

	removed := false

	if globalTS == nil {
		return
	}

	globalPromptLock.Lock()
	defer globalPromptLock.Unlock()

remove_outer:
	for ridx := 0; ridx < globalTS.IterNChildren(nil); ridx++ {
		nchildren := 0
		this_iter, err := globalTS.GetIterFromString(fmt.Sprintf("%d", ridx))
		if err != nil {
			log.Println("Strange condition; couldn't get iter of known tree index:", err)
		} else {
			nchildren = globalTS.IterNChildren(this_iter)
		}

		for cidx := 0; cidx < nchildren-1; cidx++ {
			sidx := cidx
			if cidx == nchildren {
				cidx = -1
			}

			rule, _, err := getRuleByIdx(ridx, sidx)
			if err != nil {
				break remove_outer
			} else if rule.GUID == guid {
				removeSelectedRule(ridx, sidx)
				removed = true
				break
			}
		}

	}

	if !removed {
		log.Printf("Unexpected condition: SGFW requested prompt removal for non-existent GUID %v\n", guid)
	}

}

// Needs to be locked by caller
func storeNewEntry(ts *gtk.TreeStore, iter *gtk.TreeIter, guid, path, icon, proto string, pid int, ipaddr, hostname string, port, uid, gid int, origin,
	timestamp string, is_socks bool, optstring, sandbox string, action int) {
	var colVals = [COL_NO_LAST]interface{}{}

	if is_socks {
		if (optstring != "") && (strings.Index(optstring, "SOCKS") == -1) {
			optstring = "SOCKS5 / " + optstring
		} else if optstring == "" {
			optstring = "SOCKS5"
		}
	}

	colVals[COL_NO_NREFS] = 1
	colVals[COL_NO_ICON_PIXBUF] = nil
	colVals[COL_NO_GUID] = guid
	colVals[COL_NO_PATH] = path
	colVals[COL_NO_ICON] = icon
	colVals[COL_NO_PROTO] = proto
	colVals[COL_NO_PID] = pid

	if ipaddr == "" {
		colVals[COL_NO_DSTIP] = "---"
	} else {
		colVals[COL_NO_DSTIP] = ipaddr
	}

	colVals[COL_NO_HOSTNAME] = hostname
	colVals[COL_NO_PORT] = port
	colVals[COL_NO_UID] = uid
	colVals[COL_NO_GID] = gid
	colVals[COL_NO_ORIGIN] = origin
	colVals[COL_NO_TIMESTAMP] = timestamp
	colVals[COL_NO_IS_SOCKS] = 0

	if is_socks {
		colVals[COL_NO_IS_SOCKS] = 1
	}

	colVals[COL_NO_OPTSTRING] = optstring
	colVals[COL_NO_ACTION] = action

	itheme, err := gtk.IconThemeGetDefault()
	if err != nil {
		log.Fatal("Could not load default icon theme:", err)
	}

	make_blank := false
	if icon != "" {
		pb, err := itheme.LoadIcon(icon, 24, gtk.ICON_LOOKUP_GENERIC_FALLBACK)
		if err != nil {
			log.Println("Could not load icon:", err)
			make_blank = true
		} else {
			colVals[COL_NO_ICON_PIXBUF] = pb
		}
	} else {
		make_blank = true
	}

	if make_blank {
		pb, err := gdk.PixbufNew(gdk.COLORSPACE_RGB, true, 8, 24, 24)
		if err != nil {
			log.Println("Error creating blank icon:", err)
		} else {
			colVals[COL_NO_ICON_PIXBUF] = pb

			img, err := gtk.ImageNewFromPixbuf(pb)
			if err != nil {
				log.Println("Error creating image from pixbuf:", err)
			} else {
				img.Clear()
				pb = img.GetPixbuf()
				colVals[COL_NO_ICON_PIXBUF] = pb
			}
		}

	}

	for n := 0; n < len(colVals); n++ {
		err := ts.SetValue(iter, n, colVals[n])
		if err != nil {
			log.Fatal("Unable to add row:", err)
		}
	}

	return
}

func addRequestInc(treeStore *gtk.TreeStore, guid, path, icon, proto string, pid int, ipaddr, hostname string, port, uid, gid int,
	origin, timestamp string, is_socks bool, optstring string, sandbox string, action int) bool {
	duplicated := false

	globalPromptLock.Lock()
	defer globalPromptLock.Unlock()

	for ridx := 0; ridx < globalTS.IterNChildren(nil); ridx++ {
		rule, iter, err := getRuleByIdx(ridx, -1)
		if err != nil {
			break
			// XXX: not compared: optstring/sandbox
		} else if (rule.Path == path) && (rule.Proto == proto) && (rule.Pid == pid) && (rule.Target == ipaddr) && (rule.Hostname == hostname) &&
			(rule.Port == port) && (rule.UID == uid) && (rule.GID == gid) && (rule.Origin == origin) && (rule.IsSocks == is_socks) {
			rule.nrefs++

			err := globalTS.SetValue(iter, 0, rule.nrefs)
			if err != nil {
				log.Println("Error creating duplicate firewall prompt entry:", err)
				break
			}

			duplicated = true
			subiter := globalTS.Append(iter)
			storeNewEntry(globalTS, subiter, guid, path, icon, proto, pid, ipaddr, hostname, port, uid, gid, origin, timestamp, is_socks, optstring, sandbox, action)
			break
		}

	}

	return duplicated
}

func addRequestAsync(treeStore *gtk.TreeStore, guid, path, icon, proto string, pid int, ipaddr, hostname string, port, uid, gid int,
	origin, timestamp string, is_socks bool, optstring string, sandbox string, action int) bool {
	addRequest(treeStore, guid, path, icon, proto, pid, ipaddr, hostname, port, uid, gid, origin, timestamp, is_socks,
		optstring, sandbox, action)
	return true
}

func addRequest(treeStore *gtk.TreeStore, guid, path, icon, proto string, pid int, ipaddr, hostname string, port, uid, gid int,
	origin, timestamp string, is_socks bool, optstring string, sandbox string, action int) bool {
	if treeStore == nil {
		treeStore = globalTS
		waitTimes := []int{1, 2, 5, 10}

		if treeStore == nil {
			log.Println("SGFW prompter was not ready to receive firewall request... waiting")

			for _, wtime := range waitTimes {
				time.Sleep(time.Duration(wtime) * time.Second)
				treeStore = globalTS

				if treeStore != nil {
					break
				}

				log.Println("SGFW prompter is still waiting...")
			}

		}

	}

	if treeStore == nil {
		log.Fatal("SGFW prompter GUI failed to load for unknown reasons")
	}

	if addRequestInc(treeStore, guid, path, icon, proto, pid, ipaddr, hostname, port, uid, gid, origin, timestamp, is_socks, optstring, sandbox, action) {
		fmt.Println("Request was duplicate: ", guid)
		globalPromptLock.Lock()
		toggleHover()
		globalPromptLock.Unlock()
		return true
	}

	globalPromptLock.Lock()
	defer globalPromptLock.Unlock()

	iter := treeStore.Append(nil)
	storeNewEntry(treeStore, iter, guid, path, icon, proto, pid, ipaddr, hostname, port, uid, gid, origin, timestamp, is_socks, optstring, sandbox, action)

	toggleHover()
	return true
}

func setup_settings() {
	box, err := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 0)

	if err != nil {
		log.Fatal("Unable to create settings box:", err)
	}

	scrollbox, err := gtk.ScrolledWindowNew(nil, nil)

	if err != nil {
		log.Fatal("Unable to create settings scrolled window:", err)
	}

	hLabel, err := gtk.LabelNew("Settings")

	if err != nil {
		log.Fatal("Unable to create notebook label:", err)
	}

	scrollbox.Add(box)
	scrollbox.SetSizeRequest(600, 400)

	tv, err := gtk.TreeViewNew()

	if err != nil {
		log.Fatal("Unable to create treeview:", err)
	}

	h := get_hbox()
	l := get_label("Log to file:")
	b, err := gtk.ButtonNewWithLabel("Save")

	if err != nil {
		log.Fatal("Unable to create button:", err)
	}

	h.PackStart(l, false, true, 10)
	h.PackStart(b, false, true, 10)
	h.SetMarginTop(10)
	box.Add(h)

	h = get_hbox()

	h.SetMarginTop(0)
	h.SetMarginBottom(20)
	box.Add(h)

	box.Add(tv)

	b.Connect("clicked", func() {
		fmt.Println("CLICKED")

		if err != nil {
			promptError("Unexpected error saving log file info: " + err.Error())
			return
		}

	})

	Notebook.AppendPage(scrollbox, hLabel)
}

func lsGetStr(ls *gtk.TreeStore, iter *gtk.TreeIter, idx int) (string, error) {
	val, err := globalTS.GetValue(iter, idx)
	if err != nil {
		return "", err
	}

	sval, err := val.GetString()
	if err != nil {
		return "", err
	}

	return sval, nil
}

func lsGetInt(ls *gtk.TreeStore, iter *gtk.TreeIter, idx int) (int, error) {
	val, err := globalTS.GetValue(iter, idx)
	if err != nil {
		return 0, err
	}

	ival, err := val.GoValue()
	if err != nil {
		return 0, err
	}

	return ival.(int), nil
}

func makeDecision(rule string, scope int, guid string) error {
	var dres bool
	call := dbuso.Call("AddRuleAsync", 0, uint32(scope), rule, "*", guid)

	err := call.Store(&dres)
	if err != nil {
		log.Println("Error notifying SGFW of asynchronous rule addition:", err)
		return err
	}

	fmt.Println("makeDecision remote result:", dres)
	return nil
}

/* Do we need to hold the lock while this is called? Stay safe... */
func toggleHover() {
	nitems := globalTS.IterNChildren(nil)

	mainWin.SetKeepAbove(nitems > 0)
}

func toggleValidRuleState() {
	ok := true

	// XXX: Unfortunately, this can cause deadlock since it's a part of the item removal cascade
	//	globalPromptLock.Lock()
	//	defer globalPromptLock.Unlock()

	if numSelections() <= 0 {
		ok = false
	}

	str, err := editApp.GetText()
	if err != nil || strings.Trim(str, "\t ") == "" {
		ok = false
	}

	str, err = editTarget.GetText()
	if err != nil || strings.Trim(str, "\t ") == "" {
		ok = false
	}

	str, err = editPort.GetText()
	if err != nil || strings.Trim(str, "\t ") == "" {
		ok = false
	} else {
		pval, err := strconv.Atoi(str)

		if err != nil || pval < 0 || pval > 65535 {
			ok = false
		}
	}

	if chkUser.GetActive() {
		str, err = editUser.GetText()
		if err != nil || strings.Trim(str, "\t ") == "" {
			ok = false
		}
	}

	if chkGroup.GetActive() {
		str, err = editGroup.GetText()
		if err != nil || strings.Trim(str, "\t ") == "" {
			ok = false
		}
	}

	btnApprove.SetSensitive(ok)
	btnDeny.SetSensitive(ok)
	//	btnIgnore.SetSensitive(ok)
	btnIgnore.SetSensitive(false)
}

func createCurrentRule() (ruleColumns, error) {
	rule := ruleColumns{Scope: int(sgfw.APPLY_ONCE)}
	var err error = nil

	if radioProcess.GetActive() {
		rule.Scope = int(sgfw.APPLY_PROCESS)
	} else if radioParent.GetActive() {
		return rule, errors.New("Parent process scope is unsupported at the moment")
	} else if radioSession.GetActive() {
		rule.Scope = int(sgfw.APPLY_SESSION)
	} else if radioPermanent.GetActive() {
		rule.Scope = int(sgfw.APPLY_FOREVER)
	} else {
		rule.Scope = int(sgfw.APPLY_ONCE)
	}

	rule.Path, err = editApp.GetText()
	if err != nil {
		return rule, err
	}

	ports, err := editPort.GetText()
	if err != nil {
		return rule, err
	}

	rule.Port, err = strconv.Atoi(ports)
	if err != nil {
		return rule, err
	}

	rule.Target, err = editTarget.GetText()
	if err != nil {
		return rule, err
	}

	rule.Proto = comboProto.GetActiveID()

	rule.UID, rule.GID = 0, 0
	rule.Uname, rule.Gname = "", ""

	rule.ForceTLS = chkTLS.GetActive()

	/*	Pid      int
		Origin   string */

	return rule, nil
}

func clearEditor() {
	globalIcon.Clear()
	editApp.SetText("")
	editTarget.SetText("")
	editPort.SetText("")
	editUser.SetText("")
	editGroup.SetText("")
	comboProto.SetActive(0)
	radioOnce.SetActive(true)
	radioProcess.SetActive(false)
	radioParent.SetActive(false)
	radioSession.SetActive(false)
	radioPermanent.SetActive(false)
	chkUser.SetActive(false)
	chkGroup.SetActive(false)
	chkTLS.SetActive(false)
}

func removeSelectedRule(idx, subidx int) error {
	fmt.Printf("XXX: attempting to remove idx = %v, %v\n", idx, subidx)
	ppathstr := fmt.Sprintf("%d", idx)
	pathstr := ppathstr

	if subidx > -1 {
		pathstr = fmt.Sprintf("%d:%d", idx, subidx)
	}

	iter, err := globalTS.GetIterFromString(pathstr)
	if err != nil {
		return err
	}

	nchildren := globalTS.IterNChildren(iter)

	if nchildren >= 1 {
		firstpath := fmt.Sprintf("%d:0", idx)
		citer, err := globalTS.GetIterFromString(firstpath)
		if err != nil {
			return err
		}

		gnrefs, err := globalTS.GetValue(iter, COL_NO_NREFS)
		if err != nil {
			return err
		}

		vnrefs, err := gnrefs.GoValue()
		if err != nil {
			return err
		}

		nrefs := vnrefs.(int) - 1

		for n := 0; n < COL_NO_LAST; n++ {
			val, err := globalTS.GetValue(citer, n)
			if err != nil {
				return err
			}

			if n == COL_NO_NREFS {
				err = globalTS.SetValue(iter, n, nrefs)
			} else {
				err = globalTS.SetValue(iter, n, val)
			}

			if err != nil {
				return err
			}
		}

		globalTS.Remove(citer)
		return nil
	}

	globalTS.Remove(iter)

	if subidx > -1 {
		ppath, err := gtk.TreePathNewFromString(ppathstr)
		if err != nil {
			return err
		}

		piter, err := globalTS.GetIter(ppath)
		if err != nil {
			return err
		}

		nrefs, err := lsGetInt(globalTS, piter, COL_NO_NREFS)
		if err != nil {
			return err
		}

		err = globalTS.SetValue(piter, COL_NO_NREFS, nrefs-1)
		if err != nil {
			return err
		}
	}

	toggleHover()
	return nil
}

// Needs to be locked by the caller
func numSelections() int {
	sel, err := globalTV.GetSelection()
	if err != nil {
		return -1
	}

	rows := sel.GetSelectedRows(globalTS)
	return int(rows.Length())
}

// Needs to be locked by the caller
func getRuleByIdx(idx, subidx int) (ruleColumns, *gtk.TreeIter, error) {
	rule := ruleColumns{}
	tpath := fmt.Sprintf("%d", idx)

	if subidx != -1 {
		tpath = fmt.Sprintf("%d:%d", idx, subidx)
	}

	path, err := gtk.TreePathNewFromString(tpath)
	if err != nil {
		return rule, nil, err
	}

	iter, err := globalTS.GetIter(path)
	if err != nil {
		return rule, nil, err
	}

	rule.nrefs, err = lsGetInt(globalTS, iter, COL_NO_NREFS)
	if err != nil {
		return rule, nil, err
	}

	rule.GUID, err = lsGetStr(globalTS, iter, COL_NO_GUID)
	if err != nil {
		return rule, nil, err
	}

	rule.Path, err = lsGetStr(globalTS, iter, COL_NO_PATH)
	if err != nil {
		return rule, nil, err
	}

	rule.Icon, err = lsGetStr(globalTS, iter, COL_NO_ICON)
	if err != nil {
		return rule, nil, err
	}

	rule.Proto, err = lsGetStr(globalTS, iter, COL_NO_PROTO)
	if err != nil {
		return rule, nil, err
	}

	rule.Pid, err = lsGetInt(globalTS, iter, COL_NO_PID)
	if err != nil {
		return rule, nil, err
	}

	rule.Target, err = lsGetStr(globalTS, iter, COL_NO_DSTIP)
	if err != nil {
		return rule, nil, err
	}

	rule.Hostname, err = lsGetStr(globalTS, iter, COL_NO_HOSTNAME)
	if err != nil {
		return rule, nil, err
	}

	rule.Port, err = lsGetInt(globalTS, iter, COL_NO_PORT)
	if err != nil {
		return rule, nil, err
	}

	rule.UID, err = lsGetInt(globalTS, iter, COL_NO_UID)
	if err != nil {
		return rule, nil, err
	}

	rule.GID, err = lsGetInt(globalTS, iter, COL_NO_GID)
	if err != nil {
		return rule, nil, err
	}

	rule.Origin, err = lsGetStr(globalTS, iter, COL_NO_ORIGIN)
	if err != nil {
		return rule, nil, err
	}

	rule.Timestamp, err = lsGetStr(globalTS, iter, COL_NO_TIMESTAMP)
	if err != nil {
		return rule, nil, err
	}

	rule.IsSocks = false
	is_socks, err := lsGetInt(globalTS, iter, COL_NO_IS_SOCKS)
	if err != nil {
		return rule, nil, err
	}

	if is_socks != 0 {
		rule.IsSocks = true
	}

	rule.Scope, err = lsGetInt(globalTS, iter, COL_NO_ACTION)
	if err != nil {
		return rule, nil, err
	}

	return rule, iter, nil
}

// Needs to be locked by the caller
func getSelectedRule() (ruleColumns, int, int, error) {
	rule := ruleColumns{}

	sel, err := globalTV.GetSelection()
	if err != nil {
		return rule, -1, -1, err
	}

	rows := sel.GetSelectedRows(globalTS)

	if rows.Length() <= 0 {
		return rule, -1, -1, errors.New("no selection was made")
	}

	rdata := rows.NthData(0)
	tpath := rdata.(*gtk.TreePath).String()

	subidx := -1
	ptoks := strings.Split(tpath, ":")

	if len(ptoks) > 2 {
		return rule, -1, -1, errors.New("internal error parsing selected item tree path")
	} else if len(ptoks) == 2 {
		subidx, err = strconv.Atoi(ptoks[1])
		if err != nil {
			return rule, -1, -1, err
		}
		tpath = ptoks[0]
	}

	lIndex, err := strconv.Atoi(tpath)
	if err != nil {
		return rule, -1, -1, err
	}

	//	fmt.Printf("lindex = %d : %d\n", lIndex, subidx)
	rule, _, err = getRuleByIdx(lIndex, subidx)
	if err != nil {
		return rule, -1, -1, err
	}

	return rule, lIndex, subidx, nil
}

func buttonAction(action string) {
	globalPromptLock.Lock()
	rule, idx, subidx, err := getSelectedRule()
	if err != nil {
		globalPromptLock.Unlock()
		promptError("Error occurred processing request: " + err.Error())
		return
	}

	urule, err := createCurrentRule()
	if err != nil {
		globalPromptLock.Unlock()
		promptError("Error occurred constructing new rule: " + err.Error())
		return
	}

	// Overlay the rules
	rule.Scope = urule.Scope
	//rule.Path = urule.Path
	rule.Port = urule.Port
	rule.Target = urule.Target
	rule.Proto = urule.Proto
	// rule.UID = urule.UID
	// rule.GID = urule.GID
	// rule.Uname = urule.Uname
	// rule.Gname = urule.Gname
	rule.ForceTLS = urule.ForceTLS

	fmt.Println("rule = ", rule)
	rulestr := action

	if action == "ALLOW" && rule.ForceTLS {
		rulestr += "_TLSONLY"
	}

	rulestr += "|" + rule.Proto + ":" + rule.Target + ":" + strconv.Itoa(rule.Port)
	rulestr += "|" + sgfw.RuleModeString[sgfw.RuleMode(rule.Scope)]
	fmt.Println("RULESTR = ", rulestr)
	makeDecision(rulestr, int(rule.Scope), rule.GUID)
	err = removeSelectedRule(idx, subidx)
	addRecentlyRemoved(rule.GUID)
	globalPromptLock.Unlock()
	if err == nil {
		clearEditor()
	} else {
		promptError("Error setting new rule: " + err.Error())
	}

}

func main() {
	_, err := newDbusServer()
	if err != nil {
		log.Fatal("Error:", err)
		return
	}

	dbuso, err = newDbusObjectAdd()
	if err != nil {
		log.Fatal("Failed to connect to dbus system bus: %v", err)
	}

	loadPreferences()
	gtk.Init(nil)

	// Create a new toplevel window, set its title, and connect it to the "destroy" signal to exit the GTK main loop when it is destroyed.
	mainWin, err = gtk.WindowNew(gtk.WINDOW_TOPLEVEL)

	if err != nil {
		log.Fatal("Unable to create window:", err)
	}

	mainWin.SetTitle("SGOS fw-daemon Prompter")

	mainWin.Connect("destroy", func() {
		fmt.Println("Shutting down...")
		savePreferences()
		gtk.MainQuit()
	})

	mainWin.Connect("configure-event", func() {
		w, h := mainWin.GetSize()
		userPrefs.Winwidth, userPrefs.Winheight = uint(w), uint(h)
		l, t := mainWin.GetPosition()
		userPrefs.Winleft, userPrefs.Wintop = uint(l), uint(t)
	})

	mainWin.SetPosition(gtk.WIN_POS_CENTER)

	Notebook, err = gtk.NotebookNew()

	if err != nil {
		log.Fatal("Unable to create new notebook:", err)
	}

	loglevel := "Firewall Traffic Pending Approval"

	nbLabel, err := gtk.LabelNew(loglevel)

	if err != nil {
		log.Fatal("Unable to create notebook label:", err)
	}

	box, err := gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 0)

	if err != nil {
		log.Fatal("Unable to create box:", err)
	}

	scrollbox, err := gtk.ScrolledWindowNew(nil, nil)

	if err != nil {
		log.Fatal("Unable to create scrolled window:", err)
	}

	tv, err := gtk.TreeViewNew()

	if err != nil {
		log.Fatal("Unable to create treeview:", err)
	}

	globalTV = tv
	tv.SetSizeRequest(300, 300)
	tv.SetHeadersClickable(true)

	btnApprove, err = gtk.ButtonNewWithLabel("Approve")
	if err != nil {
		log.Fatal("Unable to create button:", err)
	}

	btnDeny, err = gtk.ButtonNewWithLabel("Deny")
	if err != nil {
		log.Fatal("Unable to create button:", err)
	}

	btnIgnore, err = gtk.ButtonNewWithLabel("Ignore")
	if err != nil {
		log.Fatal("Unable to create button:", err)
	}

	btnApprove.SetSensitive(false)
	btnDeny.SetSensitive(false)
	btnIgnore.SetSensitive(false)

	bb := get_hbox()
	bb.PackStart(btnApprove, false, false, 5)
	bb.PackStart(btnDeny, false, false, 5)
	bb.PackStart(btnIgnore, false, false, 5)

	editbox := get_vbox()
	hbox := get_hbox()
	lbl := get_label("Application path:")

	globalIcon, err = gtk.ImageNew()
	if err != nil {
		log.Fatal("Unable to create image:", err)
	}

	//	globalIcon.SetFromIconName("firefox", gtk.ICON_SIZE_DND)
	editApp = get_entry("")
	editApp.SetEditable(false)
	editApp.Connect("changed", toggleValidRuleState)
	hbox.PackStart(lbl, false, false, 10)
	hbox.PackStart(editApp, true, true, 10)
	hbox.PackStart(globalIcon, false, false, 10)
	editbox.PackStart(hbox, false, false, 5)

	hbox = get_hbox()
	lbl = get_label("Target host/IP:")
	editTarget = get_entry("")
	editTarget.Connect("changed", toggleValidRuleState)
	hbox.PackStart(lbl, false, false, 10)
	hbox.PackStart(editTarget, false, false, 5)
	lbl = get_label("Port:")
	editPort = get_entry("")
	editPort.Connect("changed", toggleValidRuleState)
	hbox.PackStart(lbl, false, false, 5)
	hbox.PackStart(editPort, false, false, 5)
	lbl = get_label("Protocol:")
	comboProto = get_combobox()
	hbox.PackStart(lbl, false, true, 5)
	hbox.PackStart(comboProto, false, false, 5)
	editbox.PackStart(hbox, false, false, 5)

	hbox = get_hbox()
	lbl = get_label("Apply rule:")
	radioOnce = get_radiobutton(nil, "Once", true)
	radioProcess = get_radiobutton(radioOnce, "This Process", false)
	radioParent = get_radiobutton(radioOnce, "Parent Process", false)
	radioSession = get_radiobutton(radioOnce, "Session", false)
	radioPermanent = get_radiobutton(radioOnce, "Permanent", false)
	radioParent.SetSensitive(false)
	chkTLS = get_checkbox("Require TLS", false)
	hbox.PackStart(chkTLS, false, false, 10)
	hbox.PackStart(lbl, false, false, 20)
	hbox.PackStart(radioOnce, false, false, 5)
	hbox.PackStart(radioProcess, false, false, 5)
	hbox.PackStart(radioParent, false, false, 5)
	hbox.PackStart(radioSession, false, false, 5)
	hbox.PackStart(radioPermanent, false, false, 5)
	editbox.PackStart(hbox, false, false, 5)

	hbox = get_hbox()
	chkUser = get_checkbox("Apply to UID/username", false)
	chkUser.Connect("toggled", toggleValidRuleState)
	editUser = get_entry("")
	editUser.Connect("changed", toggleValidRuleState)
	hbox.PackStart(chkUser, false, false, 10)
	hbox.PackStart(editUser, false, false, 10)
	chkGroup = get_checkbox("Apply to GID/group:", false)
	chkGroup.Connect("toggled", toggleValidRuleState)
	editGroup = get_entry("")
	editGroup.Connect("changed", toggleValidRuleState)
	hbox.PackStart(chkGroup, false, false, 10)
	hbox.PackStart(editGroup, false, false, 10)
	editbox.PackStart(hbox, false, false, 5)

	box.PackStart(bb, false, false, 5)
	box.PackStart(editbox, false, false, 5)
	scrollbox.Add(tv)
	//	box.PackStart(tv, false, true, 5)
	box.PackStart(scrollbox, false, true, 5)

	tv.AppendColumn(createColumnText("#", COL_NO_NREFS))
	tv.AppendColumn(createColumnImg("", COL_NO_ICON_PIXBUF))

	guidcol := createColumnText("GUID", COL_NO_GUID)
	guidcol.SetVisible(false)
	tv.AppendColumn(guidcol)

	tv.AppendColumn(createColumnText("Path", COL_NO_PATH))

	icol := createColumnText("Icon", COL_NO_ICON)
	icol.SetVisible(false)
	tv.AppendColumn(icol)

	tv.AppendColumn(createColumnText("Protocol", COL_NO_PROTO))
	tv.AppendColumn(createColumnText("PID", COL_NO_PID))
	tv.AppendColumn(createColumnText("IP Address", COL_NO_DSTIP))
	tv.AppendColumn(createColumnText("Hostname", COL_NO_HOSTNAME))
	tv.AppendColumn(createColumnText("Port", COL_NO_PORT))
	tv.AppendColumn(createColumnText("UID", COL_NO_UID))
	tv.AppendColumn(createColumnText("GID", COL_NO_GID))
	tv.AppendColumn(createColumnText("Origin", COL_NO_ORIGIN))
	tv.AppendColumn(createColumnText("Timestamp", COL_NO_TIMESTAMP))

	scol := createColumnText("Is SOCKS", COL_NO_IS_SOCKS)
	scol.SetVisible(false)
	tv.AppendColumn(scol)

	tv.AppendColumn(createColumnText("Details", COL_NO_OPTSTRING))

	acol := createColumnText("Scope", COL_NO_ACTION)
	acol.SetVisible(false)
	tv.AppendColumn(acol)

	treeStore := createTreeStore(true)
	globalTS = treeStore

	tv.SetModel(treeStore)

	btnApprove.Connect("clicked", func() {
		buttonAction("ALLOW")
	})
	btnDeny.Connect("clicked", func() {
		buttonAction("DENY")
	})
	//	btnIgnore.Connect("clicked", buttonAction)

	//	tv.SetActivateOnSingleClick(true)
	tv.Connect("row-activated", func() {
		globalPromptLock.Lock()
		seldata, _, _, err := getSelectedRule()
		globalPromptLock.Unlock()
		if err != nil {
			promptError("Unexpected error reading selected rule: " + err.Error())
			return
		}

		editApp.SetText(seldata.Path)

		if seldata.Icon != "" {
			globalIcon.SetFromIconName(seldata.Icon, gtk.ICON_SIZE_DND)
		} else {
			globalIcon.Clear()
		}

		if seldata.Hostname != "" {
			editTarget.SetText(seldata.Hostname)
		} else {
			editTarget.SetText(seldata.Target)
		}

		editPort.SetText(strconv.Itoa(seldata.Port))
		radioOnce.SetActive(seldata.Scope == int(sgfw.APPLY_ONCE))
		radioProcess.SetSensitive(seldata.Scope == int(sgfw.APPLY_PROCESS))
		radioParent.SetActive(false)
		radioSession.SetActive(seldata.Scope == int(sgfw.APPLY_SESSION))
		radioPermanent.SetActive(seldata.Scope == int(sgfw.APPLY_FOREVER))

		comboProto.SetActiveID(seldata.Proto)
		chkTLS.SetActive(seldata.IsSocks)

		if seldata.Uname != "" {
			editUser.SetText(seldata.Uname)
		} else if seldata.UID != -1 {
			editUser.SetText(strconv.Itoa(seldata.UID))
		} else {
			editUser.SetText("")
		}

		if seldata.Gname != "" {
			editGroup.SetText(seldata.Gname)
		} else if seldata.GID != -1 {
			editGroup.SetText(strconv.Itoa(seldata.GID))
		} else {
			editGroup.SetText("")
		}

		chkUser.SetActive(false)
		chkGroup.SetActive(false)
		return
	})

	scrollbox.SetSizeRequest(600, 400)
	//	Notebook.AppendPage(scrollbox, nbLabel)
	Notebook.AppendPage(box, nbLabel)
	//		setup_settings()
	mainWin.Add(Notebook)

	if userPrefs.Winheight > 0 && userPrefs.Winwidth > 0 {
		// fmt.Printf("height was %d, width was %d\n", userPrefs.Winheight, userPrefs.Winwidth)
		mainWin.Resize(int(userPrefs.Winwidth), int(userPrefs.Winheight))
	} else {
		mainWin.SetDefaultSize(850, 450)
	}

	if userPrefs.Wintop > 0 && userPrefs.Winleft > 0 {
		mainWin.Move(int(userPrefs.Winleft), int(userPrefs.Wintop))
	}

	mainWin.ShowAll()
	//	mainWin.SetKeepAbove(true)

	var dres bool
	call := dbuso.Call("GetPendingRequests", 0, "*")
	err = call.Store(&dres)
	if err != nil {
		errmsg := "Could not query running SGFW instance (maybe it's not running?): " + err.Error()
		promptError(errmsg)
	} else if !dres {
		promptError("Call to sgfw did not succeed; fw-prompt may have loaded without retrieving all pending connections")
	}

	gtk.Main()
}
