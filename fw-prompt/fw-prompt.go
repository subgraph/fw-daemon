package main


import (
	"github.com/gotk3/gotk3/gtk"
	"github.com/gotk3/gotk3/glib"
	"log"
	"fmt"
	"os"
	"io/ioutil"
	"encoding/json"
	"os/user"
	"strconv"
)

type fpPreferences struct {
	Winheight uint
	Winwidth uint
	Wintop uint
	Winleft uint
}


var userPrefs fpPreferences
var mainWin *gtk.Window
var Notebook *gtk.Notebook
var globalLS *gtk.ListStore


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

func addRequest(listStore *gtk.ListStore, path, proto string, pid int, ipaddr, hostname string, port, uid, gid int, origin, optstring string) {
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

func main() {
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

//	box.Add(tv)
	box.PackStart(bb, false, false, 5)
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
		promptError("Approving firewall request.")
/*		choice := promptChoice("hmm?")

		if choice != int(gtk.RESPONSE_YES) {
			return
		} */

	})

	db.Connect("clicked", func() {
		promptError("Denying firewall request.")
	})

	db.Connect("clicked", func() {
		promptError("Ignoring firewall request.")
	})

	tv.Connect("row-activated", func() {
		fmt.Println("DOUBLE CLICK")

		sel, err := tv.GetSelection()

		if err != nil {
			promptError("Unexpected error retrieving selection: "+err.Error())
			return
		}

		rows := sel.GetSelectedRows(listStore)
		// func (v *TreeSelection) GetSelected() (model ITreeModel, iter *TreeIter, ok bool)      ???
		fmt.Println("RETURNED ROWS: ", rows.Length())

		if rows.Length() > 0 {
			rdata := rows.NthData(0)

			lIndex, err := strconv.Atoi(rdata.(*gtk.TreePath).String())

			if err != nil {
				promptError("Unexpected error reading selection data: "+err.Error())
				return
			}


			path, err := gtk.TreePathNewFromString(fmt.Sprintf("%d", lIndex))

			if err != nil {
				promptError("Unexpected error reading data from selection: "+err.Error())
				return
			}

			iter, err := listStore.GetIter(path)

			if err != nil {
				promptError("Unexpected error looking up log entry: "+err.Error())
				return
			}

			val, err := listStore.GetValue(iter, 6)

			if err != nil {
				promptError("Unexpected error getting data from log entry: "+err.Error())
				return
			}

			sval, err := val.GetString()

			if err != nil {
				promptError("Unexpected error reading data from log entry: "+err.Error())
				return
			}

			fmt.Println("HEH: ", sval)
			promptInfo(sval)
		}

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

//	addRequest(listStore, "/bin/bla", "proto", 666, "loglevel", "provider", 23, 100, 1000)
	mainWin.ShowAll()
	mainWin.SetKeepAbove(true)
	gtk.Main()
}
