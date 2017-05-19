package main


import (
	"github.com/gotk3/gotk3/gtk"
	"github.com/gotk3/gotk3/glib"
	"log"
	"fmt"
	"strconv"
	"os"
	"io/ioutil"
	"encoding/json"
	"os/user"
	"sync"
	"errors"

	"github.com/subgraph/fw-daemon/sgfw"
)


type fpPreferences struct {
	Winheight uint
	Winwidth uint
	Wintop uint
	Winleft uint
}

type decisionWaiter struct {
	Cond   *sync.Cond
	Lock	sync.Locker
	Ready  bool
	Scope  int
	Rule   string
}

type ruleColumns struct {
	Path     string
	Proto    string
	Pid      int
	Target   string
	Hostname string
	Port     int
	UID      int
	GID      int
	Origin   string
}


var userPrefs fpPreferences
var mainWin *gtk.Window
var Notebook *gtk.Notebook
var globalLS *gtk.ListStore
var globalTV *gtk.TreeView
var decisionWaiters []*decisionWaiter

var editApp, editTarget, editPort *gtk.Entry
var comboProto *gtk.ComboBoxText


func dumpDecisions() {
	fmt.Println("Total of decisions pending: ", len(decisionWaiters))
	for i := 0; i < len(decisionWaiters); i++ {
		fmt.Printf("%d ready = %v, rule = %v\n", i+1, decisionWaiters[i].Ready, decisionWaiters[i].Rule)
	}
}

func addDecision() *decisionWaiter {
	decision := decisionWaiter{Lock: &sync.Mutex{}, Ready: false, Scope: int(sgfw.APPLY_ONCE), Rule: ""}
	decision.Cond = sync.NewCond(decision.Lock)
	decisionWaiters = append(decisionWaiters, &decision)
	return &decision
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
	scrollbox.SetSizeRequest(600, 100)

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
		fmt.Fprintf(os.Stderr, "Error: could not determine location of user preferences file:", err, "\n");
		return ""
	}

	prefPath := usr.HomeDir + "/.fwprompt.json"
	return prefPath
}

func savePreferences() bool {
	usr, err := user.Current()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not determine location of user preferences file:", err, "\n");
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
		fmt.Fprintf(os.Stderr, "Error: could not determine location of user preferences file: %v", err, "\n");
		return false
	}

	prefPath := usr.HomeDir + "/.fwprompt.json"
	fmt.Println("xxxxxxxxxxxxxxxxxxxxxx preferences path = ", prefPath)

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

func createColumn(title string, id int) *gtk.TreeViewColumn {
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

func createListStore(general bool) *gtk.ListStore {
	colData := []glib.Type{glib.TYPE_INT, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_INT, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_INT, glib.TYPE_INT, glib.TYPE_INT, glib.TYPE_STRING, glib.TYPE_STRING}
	listStore, err := gtk.ListStoreNew(colData...)

	if err != nil {
		log.Fatal("Unable to create list store:", err)
	}

	return listStore
}

func addRequest(listStore *gtk.ListStore, path, proto string, pid int, ipaddr, hostname string, port, uid, gid int, origin, optstring string) *decisionWaiter {
	if listStore == nil {
		listStore = globalLS
	}

	iter := listStore.Append()

	colVals := make([]interface{}, 11)
	colVals[0] = 1
	colVals[1] = path
	colVals[2] = proto
	colVals[3] = pid
	colVals[4] = ipaddr
	colVals[5] = hostname
	colVals[6] = port
	colVals[7] = uid
	colVals[8] = gid
	colVals[9] = origin
	colVals[10] = optstring

	colNums := make([]int, len(colVals))

	for n := 0; n < len(colVals); n++ {
		colNums[n] = n
	}

	err := listStore.Set(iter, colNums, colVals)

	if err != nil {
		log.Fatal("Unable to add row:", err)
	}

	decision := addDecision()
	dumpDecisions()
	return decision
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
	scrollbox.SetSizeRequest(600, 800)

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
			promptError("Unexpected error saving log file info: "+err.Error())
			return
		}

	})

	Notebook.AppendPage(scrollbox, hLabel)
}

func lsGetStr(ls *gtk.ListStore, iter *gtk.TreeIter, idx int) (string, error) {
	val, err := globalLS.GetValue(iter, idx)
	if err != nil {
		return "", err
	}

	sval, err := val.GetString()
	if err != nil {
		return "", err
	}

	return sval, nil
}

func lsGetInt(ls *gtk.ListStore, iter *gtk.TreeIter, idx int) (int, error) {
	val, err := globalLS.GetValue(iter, idx)
	if err != nil {
		return 0, err
	}

	ival, err := val.GoValue()
	if err != nil {
		return 0, err
	}

	return ival.(int), nil
}

func makeDecision(idx int, rule string, scope int) {
	decisionWaiters[idx].Cond.L.Lock()
	decisionWaiters[idx].Rule = rule
	decisionWaiters[idx].Scope = scope
	decisionWaiters[idx].Ready = true
	decisionWaiters[idx].Cond.Signal()
	decisionWaiters[idx].Cond.L.Unlock()
}

func createCurrentRule() (ruleColumns, error) {
	rule := ruleColumns{}
	var err error = nil

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
/*	Pid      int
	Origin   string */

	return rule, nil
}

func clearEditor() {
	editApp.SetText("")
	editTarget.SetText("")
	editPort.SetText("")
	comboProto.SetActive(0)
/*	ronce.SetActive(true)
	rprocess.SetActive(false)
	rparent.SetActive(false)
	rsession.SetActive(false)
	rpermanent.SetActive(false) */
}

func removeSelectedRule(idx int) error {
	fmt.Println("XXX: attempting to remove idx = ", idx)
	path, err := gtk.TreePathNewFromString(fmt.Sprintf("%d", idx))
	if err != nil {
		return err
	}

	iter, err := globalLS.GetIter(path)
	if err != nil {
		return err
	}

	ok := globalLS.Remove(iter)

	// XXX: hmmm? why does this work? shouldn't it be the opposite?
	if ok {
		return errors.New("Unexpected error removing rule from list")
	}

	decisionWaiters = append(decisionWaiters[:idx], decisionWaiters[idx+1:]...)
	return nil
}

func getSelectedRule() (ruleColumns, int, error) {
	rule := ruleColumns{}

	sel, err := globalTV.GetSelection()
	if err != nil {
		return rule, -1, err
	}

	rows := sel.GetSelectedRows(globalLS)
	fmt.Println("RETURNED ROWS: ", rows.Length())

	if rows.Length() <= 0 {
		return rule, -1, errors.New("No selection was made")
	}

	rdata := rows.NthData(0)
	lIndex, err := strconv.Atoi(rdata.(*gtk.TreePath).String())
	if err != nil {
		return rule, -1, err
	}

	fmt.Println("lindex = ", lIndex)
	path, err := gtk.TreePathNewFromString(fmt.Sprintf("%d", lIndex))
	if err != nil {
		return rule, -1, err
	}

	iter, err := globalLS.GetIter(path)
	if err != nil {
		return rule, -1, err
	}

	rule.Path, err = lsGetStr(globalLS, iter, 1)
	if err != nil {
		return rule, -1, err
	}

	rule.Proto, err = lsGetStr(globalLS, iter, 2)
	if err != nil {
		return rule, -1, err
	}

	rule.Pid, err = lsGetInt(globalLS, iter, 3)
	if err != nil {
		return rule, -1, err
	}

	rule.Target, err = lsGetStr(globalLS, iter, 4)
	if err != nil {
		return rule, -1, err
	}

	rule.Hostname, err = lsGetStr(globalLS, iter, 5)
	if err != nil {
		return rule, -1, err
	}

	rule.Port, err = lsGetInt(globalLS, iter, 6)
	if err != nil {
		return rule, -1, err
	}

	rule.UID, rule.GID = 0, 0

	rule.Origin, err = lsGetStr(globalLS, iter, 9)
	if err != nil {
		return rule, -1, err
	}

	return rule, lIndex, nil
}

func main() {
	decisionWaiters = make([]*decisionWaiter, 0)
	_, err := newDbusServer();
	if err != nil {
		log.Fatal("Error:", err)
		return
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

	loglevel := "Pending Approval"

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

	scrollbox.Add(box)


	tv, err := gtk.TreeViewNew()

	if err != nil {
		log.Fatal("Unable to create treeview:", err)
	}

	globalTV = tv
	tv.SetSizeRequest(300, 300)
	tv.SetHeadersClickable(true)

	ab, err := gtk.ButtonNewWithLabel("Approve")
	if err != nil {
		log.Fatal("Unable to create button:", err)
	}

	db, err := gtk.ButtonNewWithLabel("Deny")
	if err != nil {
		log.Fatal("Unable to create button:", err)
	}

	ib, err := gtk.ButtonNewWithLabel("Ignore")
	if err != nil {
		log.Fatal("Unable to create button:", err)
	}

	bb := get_hbox()
	bb.PackStart(ab, false, false, 5)
	bb.PackStart(db, false, false, 5)
	bb.PackStart(ib, false, false, 5)

	editbox := get_vbox()
	hbox := get_hbox()
	lbl := get_label("Application path:")
	editApp = get_entry("")
	hbox.PackStart(lbl, false, false, 10)
	hbox.PackStart(editApp, false, false, 5)
	editbox.PackStart(hbox, false, false, 5)

	hbox = get_hbox()
	lbl = get_label("Target host/IP:")
	editTarget = get_entry("")
	hbox.PackStart(lbl, false, false, 10)
	hbox.PackStart(editTarget, false, false, 5)
	lbl = get_label("Port:")
	editPort = get_entry("")
	hbox.PackStart(lbl, false, false, 5)
	hbox.PackStart(editPort, false, false, 5)
	lbl = get_label("Protocol:")
	comboProto = get_combobox()
	hbox.PackStart(lbl, false, true, 5)
	hbox.PackStart(comboProto, false, false, 5)
	editbox.PackStart(hbox, false, false, 5)

	hbox = get_hbox()
	lbl = get_label("Apply rule:")
	ronce := get_radiobutton(nil, "Once", true)
	rprocess := get_radiobutton(ronce, "This Process", false)
	rparent := get_radiobutton(ronce, "Parent Process", false)
	rsession := get_radiobutton(ronce, "Session", false)
	rpermanent := get_radiobutton(ronce, "Permanent", false)
	hbox.PackStart(lbl, false, false, 10)
	hbox.PackStart(ronce, false, false, 5)
	hbox.PackStart(rprocess, false, false, 5)
	hbox.PackStart(rparent, false, false, 5)
	hbox.PackStart(rsession, false, false, 5)
	hbox.PackStart(rpermanent, false, false, 5)
	editbox.PackStart(hbox, false, false, 5)

	box.PackStart(bb, false, false, 5)
	box.PackStart(editbox, false, false, 5)
	box.PackStart(tv, false, true, 5)

	tv.AppendColumn(createColumn("#", 0))
	tv.AppendColumn(createColumn("Path", 1))
	tv.AppendColumn(createColumn("Protocol", 2))
	tv.AppendColumn(createColumn("PID", 3))
	tv.AppendColumn(createColumn("IP Address", 4))
	tv.AppendColumn(createColumn("Hostname", 5))
	tv.AppendColumn(createColumn("Port", 6))
	tv.AppendColumn(createColumn("UID", 7))
	tv.AppendColumn(createColumn("GID", 8))
	tv.AppendColumn(createColumn("Origin", 9))
	tv.AppendColumn(createColumn("Details", 10))

	listStore := createListStore(true)
	globalLS = listStore

	tv.SetModel(listStore)

	ab.Connect("clicked", func() {
		rule, idx, err := getSelectedRule()
		if err != nil {
			promptError("Error occurred processing request: "+err.Error())
			return
		}

		rule, err = createCurrentRule()
		if err != nil {
			promptError("Error occurred constructing new rule: "+err.Error())
			return
		}

		fmt.Println("rule = ", rule)
		rulestr := "ALLOW|" + rule.Proto + ":" + rule.Target + ":" + strconv.Itoa(rule.Port)
		fmt.Println("RULESTR = ", rulestr)
		makeDecision(idx, rulestr, int(sgfw.APPLY_ONCE))
		fmt.Println("Decision made.")
		err = removeSelectedRule(idx)
		if err == nil {
			clearEditor()
		} else {
			promptError("Error setting new rule: "+err.Error())
		}
	})

	db.Connect("clicked", func() {
		rule, idx, err := getSelectedRule()
		if err != nil {
			promptError("Error occurred processing request: "+err.Error())
			return
		}

		rule, err = createCurrentRule()
		if err != nil {
			promptError("Error occurred constructing new rule: "+err.Error())
			return
		}

		fmt.Println("rule = ", rule)
		rulestr := "DENY|" + rule.Proto + ":" + rule.Target + ":" + strconv.Itoa(rule.Port)
		fmt.Println("RULESTR = ", rulestr)
		makeDecision(idx, rulestr, int(sgfw.APPLY_ONCE))
		fmt.Println("Decision made.")
		err = removeSelectedRule(idx)
		if err == nil {
			clearEditor()
		} else {
			promptError("Error setting new rule: "+err.Error())
		}
	})

	ib.Connect("clicked", func() {
		promptError("Ignoring firewall request.")
		return
/*		promptError("Ignoring firewall request.")
		fmt.Println("LOCKING")
		decisionWaiters[0].Cond.L.Lock()
		decisionWaiters[0].Ready = true
		decisionWaiters[0].Rule = "bloop done"
		fmt.Println("SIGNALING")
		decisionWaiters[0].Cond.Signal()
		fmt.Println("SIGNALED")
		fmt.Println("UNLOCKING")
		decisionWaiters[0].Cond.L.Unlock() */
	})

	tv.Connect("row-activated", func() {
		seldata, _, err := getSelectedRule()
		if err != nil {
			promptError("Unexpected error reading selected rule: "+err.Error())
			return
		}

		editApp.SetText(seldata.Path)

		if seldata.Hostname != "" {
			editTarget.SetText(seldata.Hostname)
		} else {
			editTarget.SetText(seldata.Target)
		}

		editPort.SetText(strconv.Itoa(seldata.Port))
		ronce.SetActive(true)
		rprocess.SetActive(false)
		rparent.SetActive(false)
		rsession.SetActive(false)
		rpermanent.SetActive(false)
		comboProto.SetActiveID(seldata.Proto)

		return
//		promptInfo(sval)
	})


	scrollbox.SetSizeRequest(600, 800)
	Notebook.AppendPage(scrollbox, nbLabel)
	setup_settings()
	mainWin.Add(Notebook)

	if userPrefs.Winheight > 0 && userPrefs.Winwidth > 0 {
		fmt.Printf("height was %d, width was %d\n", userPrefs.Winheight, userPrefs.Winwidth)
		mainWin.Resize(int(userPrefs.Winwidth), int(userPrefs.Winheight))
	} else {
		mainWin.SetDefaultSize(800, 600)
	}

	if userPrefs.Wintop > 0 && userPrefs.Winleft > 0 {
		mainWin.Move(int(userPrefs.Winleft), int(userPrefs.Wintop))
	}

	mainWin.ShowAll()
	mainWin.SetKeepAbove(true)
	gtk.Main()
}
