package main

import (
	"errors"
	"fmt"
	"log"
	spath "path"
	"strings"
	"strconv"
	"sync"
	"time"

	"github.com/subgraph/fw-daemon/sgfw"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

type Prompt struct {
	app *fwApp
	tv *gtk.TreeView
	ts *gtk.TreeStore
	stack *gtk.Stack
	pecols []*gtk.TreeViewColumn
	pncol *gtk.TreeViewColumn
	promptLock *sync.Mutex
	recentLock *sync.Mutex
	config *sgfw.FirewallConfigs
	recentlyRemoved []string
}

const (
	COL_NO_NREFS = iota
	COL_NO_ICON_PIXBUF
	COL_NO_GUID
	COL_NO_PATH
	COL_NO_SANDBOX
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
	COL_NO_FILLER
	COL_NO_LAST
)


type ruleColumns struct {
	nrefs     int
	Path      string
	Sandbox     string
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

func createPromptView(app *fwApp, sw *gtk.ScrolledWindow) (*Prompt, error) {
	var err error
	p := &Prompt{}
	p.app = app
	p.promptLock = &sync.Mutex{}
	p.recentLock = &sync.Mutex{}
	
	p.tv, err = gtk.TreeViewNew()

	if err != nil {
		return nil, err 
	}

	p.tv.SetSizeRequest(300, 300)
	p.tv.SetHeadersClickable(true)
	p.tv.SetEnableSearch(false)

	p.tv.AppendColumn(createColumnText("#", COL_NO_NREFS))
	p.tv.AppendColumn(createColumnImg("", COL_NO_ICON_PIXBUF))

	guidcol := createColumnText("GUID", COL_NO_GUID)
	guidcol.SetVisible(false)
	p.tv.AppendColumn(guidcol)

	p.tv.AppendColumn(createColumnText("Path", COL_NO_PATH))

	sbcol := createColumnText("Realm", COL_NO_SANDBOX)
	//sbcol.SetVisible(true)
	p.tv.AppendColumn(sbcol)

	icol := createColumnText("Icon", COL_NO_ICON)
	icol.SetVisible(false)
	p.tv.AppendColumn(icol)

	var pecol *gtk.TreeViewColumn
	p.tv.AppendColumn(createColumnText("Protocol", COL_NO_PROTO))
	pecol = createColumnText("PID", COL_NO_PID)
	p.tv.AppendColumn(pecol)
	p.pecols = append(p.pecols, pecol)
	p.tv.AppendColumn(createColumnText("IP Address", COL_NO_DSTIP))
	pecol = createColumnText("Hostname", COL_NO_HOSTNAME)
	pecol.SetMinWidth(64)
	p.tv.AppendColumn(pecol)
	p.tv.AppendColumn(createColumnText("Port", COL_NO_PORT))
	pecol = createColumnText("UID", COL_NO_UID)
	p.tv.AppendColumn(pecol)
	p.pecols = append(p.pecols, pecol)
	pecol = createColumnText("GID", COL_NO_GID)
	p.tv.AppendColumn(pecol)
	p.pecols = append(p.pecols, pecol)
	pecol = createColumnText("Origin", COL_NO_ORIGIN)
	p.tv.AppendColumn(pecol)
	p.pecols = append(p.pecols, pecol)
	pecol = createColumnText("Timestamp", COL_NO_TIMESTAMP)
	p.tv.AppendColumn(pecol)
	p.pecols = append(p.pecols, pecol)

	scol := createColumnText("Is SOCKS", COL_NO_IS_SOCKS)
	scol.SetVisible(false)
	p.tv.AppendColumn(scol)

	pecol = createColumnText("Details", COL_NO_OPTSTRING)
	p.tv.AppendColumn(pecol)
	p.pecols = append(p.pecols, pecol)

	acol := createColumnText("Scope", COL_NO_ACTION)
	acol.SetVisible(false)
	p.tv.AppendColumn(acol)

	pncol := createColumnImg("", COL_NO_FILLER)
	pncol.SetVisible(false)
	pncol.SetSortIndicator(false)
	p.tv.AppendColumn(pncol)
	p.pncol = pncol

	p.togglePECols()

	p.ts = createTreeStore(true)
	
	p.tv.SetModel(p.ts)
	p.tv.Connect("row-activated", func() {
		p.promptLock.Lock()
		seldata, _, _, err := p.getSelectedRule()
		p.promptLock.Unlock()
		if err != nil {
			warnDialog(&p.app.win.Window, "Unexpected error reading selected rule: " + err.Error() + "\n" + fmt.Sprintf("%+v", seldata))
			return
		}

		rl := &ruleList{app: p.app}
		target := seldata.Hostname
		if target == "" {
			target = seldata.Target
		}
		rr := &ruleRow{ rl: rl, rule: &sgfw.DbusRule{
			Path: seldata.Path,
			Sandbox: seldata.Sandbox,
			Pid: uint32(seldata.Pid),
			UID: int32(seldata.UID),
			GID: int32(seldata.GID),
			Target: strings.Join([]string{target, strconv.Itoa(seldata.Port)}, ":"),
			Proto: seldata.Proto,
			Origin: seldata.Origin,
			IsSocks: seldata.IsSocks,
		}}
		redit := newRuleAdd(rr, DIALOG_MODE_PROMPT)
		redit.update()
		redit.run(seldata.GUID, p.buttonAction)
		return
	})

	p.app.appendConfigCallback(p.togglePECols)

	sw.SetSizeRequest(600, 400)
	p.createShortcuts()
	sw.Add(p.tv)
	return p, nil
}

func (p *Prompt) HasItems() bool {
	return p.ts.IterNChildren(nil) > 0
}

func (p *Prompt) togglePECols() {
	v := p.app.Config.PromptExpanded
	for _, pc := range p.pecols {
		pc.SetVisible(v)
	}
	p.pncol.SetVisible(!v)
}

func (p *Prompt) createShortcuts() {
	// We register here since the shortcuts are bound in an ephemeral window
	p.app.RegisterShortcutHelp("<Alt>a", "prompt", "Allow")
	p.app.RegisterShortcutHelp("<Alt>d Escape", "prompt", "Deny")
	p.app.RegisterShortcutHelp("<Alt>c", "prompt", "Cancel")
	p.app.RegisterShortcutHelp("<Alt>h", "prompt", "Select the hostname/IP entry")
	p.app.RegisterShortcutHelp("<Alt>p", "prompt", "Select the port entry")
	p.app.RegisterShortcutHelp("<Alt>o", "prompt", "Select protocol")
	p.app.RegisterShortcutHelp("<Alt>t", "prompt", "Toggle allow TLS only")
	p.app.RegisterShortcutHelp("<Alt>s", "prompt", "Select scope")
	p.app.RegisterShortcutHelp("<Alt>u", "prompt", "Toggle apply UID")
	p.app.RegisterShortcutHelp("<Alt>g", "prompt", "Toggle apply GID")

	p.app.ConnectShortcut("<Primary><Alt>space", "", "", p.app.win.Window, func (win gtk.Window) {
		vis := p.app.tlStack.GetVisibleChildName()
		iter, found := p.ts.GetIterFirst()
		if iter == nil || found == false && vis != "prompt" {
			return
		}
		if vis != "prompt" {
			p.app.tlStack.SetVisibleChildFull("prompt", gtk.STACK_TRANSITION_TYPE_SLIDE_LEFT_RIGHT)
			p.app.onStackChanged()
		}
		pi, _ := p.ts.GetPath(iter)
		if pi != nil {
			p.tv.SetCursor(pi, nil, false)
			p.tv.Emit("row-activated")
		}
	})
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
	colData := []glib.Type{glib.TYPE_INT, glib.TYPE_OBJECT, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_INT, glib.TYPE_STRING,
		glib.TYPE_STRING, glib.TYPE_INT, glib.TYPE_INT, glib.TYPE_INT, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_INT, glib.TYPE_STRING, glib.TYPE_INT, glib.TYPE_OBJECT}

	treeStore, err := gtk.TreeStoreNew(colData...)
	if err != nil {
		log.Fatal("Unable to create list store:", err)
	}

	return treeStore
}


func (p *Prompt) addRequestInc(guid, path, icon, proto string, pid int, ipaddr, hostname string, port, uid, gid int,
	origin, timestamp string, is_socks bool, optstring string, sandbox string, action int) bool {
	duplicated := false

	p.promptLock.Lock()
	defer p.promptLock.Unlock()
	for ridx := 0; ridx < p.ts.IterNChildren(nil); ridx++ {
		rule, iter, err := p.getRuleByIdx(ridx, -1)
		if err != nil {
			break
			// XXX: not compared: optstring/sandbox
		} else if (rule.Path == path) && (rule.Proto == proto) && (rule.Pid == pid) && (rule.Target == ipaddr) && (rule.Hostname == hostname) &&
			(rule.Port == port) && (rule.UID == uid) && (rule.GID == gid) && (rule.Origin == origin) && (rule.IsSocks == is_socks) {
			rule.nrefs++

			err := p.ts.SetValue(iter, 0, rule.nrefs)
			if err != nil {
				fmt.Println("Error creating duplicate firewall prompt entry:", err)
				break
			}

			duplicated = true
			subiter := p.ts.Append(iter)
			p.storeNewEntry(subiter, guid, path, sandbox, icon, proto, pid, ipaddr, hostname, port, uid, gid, origin, timestamp, is_socks, optstring, action)
			break
		}

	}

	return duplicated
}

func (p *Prompt) AddRequest(guid, path, icon, proto string, pid int, ipaddr, hostname string, port, uid, gid int,
	origin, timestamp string, is_socks bool, optstring string, sandbox string, action int) bool {
	if p.ts == nil {
		waitTimes := []int{1, 2, 5, 10}

		if p.ts == nil {
			fmt.Println("SGFW prompter was not ready to receive firewall request... waiting")

			for _, wtime := range waitTimes {
				time.Sleep(time.Duration(wtime) * time.Second)

				if p.ts != nil {
					break
				}

				fmt.Println("SGFW prompter is still waiting...")
			}
		}
	}

	if p.ts == nil {
		log.Fatal("SGFW prompter GUI failed to load for unknown reasons")
	}

	if p.addRequestInc(guid, path, icon, proto, pid, ipaddr, hostname, port, uid, gid, origin, timestamp, is_socks, optstring, sandbox, action) {
		fmt.Println("Request was duplicate: ", guid)
		p.promptLock.Lock()
		p.toggleHover()
		p.promptLock.Unlock()
		return true
	}

	p.promptLock.Lock()
	defer p.promptLock.Unlock()

	iter := p.ts.Append(nil)
	p.storeNewEntry(iter, guid, path, sandbox, icon, proto, pid, ipaddr, hostname, port, uid, gid, origin, timestamp, is_socks, optstring, action)

	p.toggleHover()
	return true
}

// Needs to be locked by caller
func (p *Prompt)storeNewEntry(iter *gtk.TreeIter, guid, path, sandbox, icon, proto string, pid int, ipaddr, hostname string, port, uid, gid int, origin,
	timestamp string, is_socks bool, optstring string, action int) {
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
	colVals[COL_NO_SANDBOX] = sandbox
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
	colVals[COL_NO_FILLER] = nil

	itheme, err := gtk.IconThemeGetDefault()
	if err != nil {
		log.Fatal("Could not load default icon theme:", err)
	}

	in := []string{spath.Base(path)}
	if sandbox != "" {
		in = append([]string{sandbox}, in...)
	}
	if icon != "" {
		in = append(in, icon)
	}
	in = append(in, "terminal")
	if path == "[unknown]" {
		in = []string{"image-missing"}
	}

	for _, ia := range in {
		pb, _ := itheme.LoadIcon(ia, int(gtk.ICON_SIZE_BUTTON), gtk.ICON_LOOKUP_GENERIC_FALLBACK)
		if pb != nil {
			colVals[COL_NO_ICON_PIXBUF] = pb
			break
		}
	}

	pb, err := gdk.PixbufNew(gdk.COLORSPACE_RGB, true, 8, 24, 24)
	if err != nil {
		log.Println("Error creating blank icon:", err)
	} else {
		colVals[COL_NO_FILLER] = pb

		img, err := gtk.ImageNewFromPixbuf(pb)
		if err != nil {
			log.Println("Error creating image from pixbuf:", err)
		} else {
			img.Clear()
			pb = img.GetPixbuf()
			colVals[COL_NO_FILLER] = pb
		}
	}

	for n := 0; n < len(colVals); n++ {
		err := p.ts.SetValue(iter, n, colVals[n])
		if err != nil {
			log.Fatal("Unable to add row:", err)
		}
	}

	return
}

func (p *Prompt) getRuleByIdx(idx, subidx int) (ruleColumns, *gtk.TreeIter, error) {
	rule := ruleColumns{}
	tpath := fmt.Sprintf("%d", idx)

	if subidx != -1 {
		tpath = fmt.Sprintf("%d:%d", idx, subidx)
	}

	path, err := gtk.TreePathNewFromString(tpath)
	if err != nil {
		return rule, nil, err
	}

	iter, err := p.ts.GetIter(path)
	if err != nil {
		return rule, nil, err
	}

	rule.nrefs, err = p.lsGetInt(iter, COL_NO_NREFS)
	if err != nil {
		return rule, nil, err
	}

	rule.GUID, err = p.lsGetStr(iter, COL_NO_GUID)
	if err != nil {
		return rule, nil, err
	}

	rule.Path, err = p.lsGetStr(iter, COL_NO_PATH)
	if err != nil {
		return rule, nil, err
	}

	rule.Sandbox, err = p.lsGetStr(iter, COL_NO_SANDBOX)
	if err != nil {
		return rule, nil, err
	}

	rule.Icon, err = p.lsGetStr(iter, COL_NO_ICON)
	if err != nil {
		return rule, nil, err
	}

	rule.Proto, err = p.lsGetStr(iter, COL_NO_PROTO)
	if err != nil {
		return rule, nil, err
	}

	rule.Pid, err = p.lsGetInt(iter, COL_NO_PID)
	if err != nil {
		return rule, nil, err
	}

	rule.Target, err = p.lsGetStr(iter, COL_NO_DSTIP)
	if err != nil {
		return rule, nil, err
	}

	rule.Hostname, err = p.lsGetStr(iter, COL_NO_HOSTNAME)
	if err != nil {
		return rule, nil, err
	}

	rule.Port, err = p.lsGetInt(iter, COL_NO_PORT)
	if err != nil {
		return rule, nil, err
	}

	rule.UID, err = p.lsGetInt(iter, COL_NO_UID)
	if err != nil {
		return rule, nil, err
	}

	rule.GID, err = p.lsGetInt(iter, COL_NO_GID)
	if err != nil {
		return rule, nil, err
	}

	rule.Origin, err = p.lsGetStr(iter, COL_NO_ORIGIN)
	if err != nil {
		return rule, nil, err
	}

	rule.Timestamp, err = p.lsGetStr(iter, COL_NO_TIMESTAMP)
	if err != nil {
		return rule, nil, err
	}

	rule.IsSocks = false
	is_socks, err := p.lsGetInt(iter, COL_NO_IS_SOCKS)
	if err != nil {
		return rule, nil, err
	}

	if is_socks != 0 {
		rule.IsSocks = true
	}

	rule.Scope, err = p.lsGetInt(iter, COL_NO_ACTION)
	if err != nil {
		return rule, nil, err
	}

	return rule, iter, nil
}

func (p *Prompt) lsGetInt(iter *gtk.TreeIter, idx int) (int, error) {
	val, err := p.ts.GetValue(iter, idx)
	if err != nil {
		return 0, err
	}

	ival, err := val.GoValue()
	if err != nil {
		return 0, err
	}

	return ival.(int), nil
}


func (p *Prompt) lsGetStr(iter *gtk.TreeIter, idx int) (string, error) {
	val, err := p.ts.GetValue(iter, idx)
	if err != nil {
		return "", err
	}

	sval, err := val.GetString()
	if err != nil {
		return "", err
	}

	return sval, nil
}

func (p *Prompt) toggleHover() {
	nitems := p.ts.IterNChildren(nil)
	stack := p.app.tlStack.GetChildByName("prompt")

	if nitems > 0 {
		if p.app.Settings.GetToplevelPrompt() {
			//p.win.SetModal(true)
			p.app.win.Deiconify()
			p.app.win.SetKeepAbove(true)
			p.app.win.Stick()
		}
		p.app.win.SetUrgencyHint(true)
		p.app.win.Present()
		if p.app.tlStack.GetVisibleChildName() != "prompt" {
			err := p.app.tlStack.ChildSetProperty(stack, "needs-attention", true)
			if err != nil {
				fmt.Println("Error setting stack attention")
			}
		}
	} else {
		//p.win.SetModal(false)
		p.app.win.SetUrgencyHint(false)
		if p.app.Settings.GetToplevelPrompt() {
			p.app.win.SetKeepAbove(false)
			p.app.win.Unstick()
		}
		p.app.tlStack.ChildSetProperty(stack, "needs-attention", false)
	}
}

// Needs to be locked by the caller
func (p *Prompt) getSelectedRule() (ruleColumns, int, int, error) {
	rule := ruleColumns{}

	sel, err := p.tv.GetSelection()
	if err != nil {
		return rule, -1, -1, err
	}

	rows := sel.GetSelectedRows(p.ts)

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
	rule, _, err = p.getRuleByIdx(lIndex, subidx)
	if err != nil {
		return rule, -1, -1, err
	}

	return rule, lIndex, subidx, nil
}

// Needs to be locked by the caller
func (p *Prompt) numSelections() int {
	sel, err := p.tv.GetSelection()
	if err != nil {
		return -1
	}

	rows := sel.GetSelectedRows(p.ts)
	return int(rows.Length())
}


func (p *Prompt) removeSelectedRule(idx, subidx int) error {
	fmt.Printf("XXX: attempting to remove idx = %v, %v\n", idx, subidx)
	ppathstr := fmt.Sprintf("%d", idx)
	pathstr := ppathstr

	if subidx > -1 {
		pathstr = fmt.Sprintf("%d:%d", idx, subidx)
	}

	iter, err := p.ts.GetIterFromString(pathstr)
	if err != nil {
		return err
	}

	nchildren := p.ts.IterNChildren(iter)

	if nchildren >= 1 {
		firstpath := fmt.Sprintf("%d:0", idx)
		citer, err := p.ts.GetIterFromString(firstpath)
		if err != nil {
			return err
		}

		gnrefs, err := p.ts.GetValue(iter, COL_NO_NREFS)
		if err != nil {
			return err
		}

		vnrefs, err := gnrefs.GoValue()
		if err != nil {
			return err
		}

		nrefs := vnrefs.(int) - 1

		for n := 0; n < COL_NO_LAST; n++ {
			val, err := p.ts.GetValue(citer, n)
			if err != nil {
				return err
			}

			if n == COL_NO_NREFS {
				err = p.ts.SetValue(iter, n, nrefs)
			} else {
				err = p.ts.SetValue(iter, n, val)
			}

			if err != nil {
				return err
			}
		}

		p.ts.Remove(citer)
		return nil
	}

	p.ts.Remove(iter)

	if subidx > -1 {
		ppath, err := gtk.TreePathNewFromString(ppathstr)
		if err != nil {
			return err
		}

		piter, err := p.ts.GetIter(ppath)
		if err != nil {
			return err
		}

		nrefs, err := p.lsGetInt(piter, COL_NO_NREFS)
		if err != nil {
			return err
		}

		err = p.ts.SetValue(piter, COL_NO_NREFS, nrefs-1)
		if err != nil {
			return err
		}
	}

	p.toggleHover()
	return nil
}

func (p *Prompt) addRecentlyRemoved(guid string) {
	p.recentLock.Lock()
	defer p.recentLock.Unlock()
	fmt.Println("RECENTLY REMOVED: ", guid)
	p.recentlyRemoved = append(p.recentlyRemoved, guid)
}

func (p *Prompt) wasRecentlyRemoved(guid string) bool {
	p.recentLock.Lock()
	defer p.recentLock.Unlock()

	for gind, g := range p.recentlyRemoved {
		if g == guid {
			p.recentlyRemoved = append(p.recentlyRemoved[:gind], p.recentlyRemoved[gind+1:]...)
			return true
		}
	}

	return false
}

func (p *Prompt) RemoveRequest(guid string) {
	if p.wasRecentlyRemoved(guid) {
		fmt.Printf("Entry for %s was recently removed; deleting from cache\n", guid)
		return
	}

	removed := false

	if p.ts == nil {
		return
	}

	p.promptLock.Lock()
	defer p.promptLock.Unlock()

remove_outer:
	for ridx := 0; ridx < p.ts.IterNChildren(nil); ridx++ {
		nchildren := 0
		this_iter, err := p.ts.GetIterFromString(fmt.Sprintf("%d", ridx))
		if err != nil {
			log.Println("Strange condition; couldn't get iter of known tree index:", err)
		} else {
			nchildren = p.ts.IterNChildren(this_iter)
		}

		for cidx := 0; cidx < nchildren-1; cidx++ {
			sidx := cidx
			if cidx == nchildren {
				cidx = -1
			}

			rule, _, err := p.getRuleByIdx(ridx, sidx)
			if err != nil {
				break remove_outer
			} else if rule.GUID == guid {
				p.removeSelectedRule(ridx, sidx)
				removed = true
				break
			}
		}
	}

	if !removed {
		fmt.Printf("Unexpected condition: SGFW requested prompt removal for non-existent GUID %v\n", guid)
	}
}

func (p *Prompt) RemoveAll() {
	p.promptLock.Lock()
	defer p.promptLock.Unlock()
	p.recentLock.Lock()
	defer p.recentLock.Unlock()

	p.recentlyRemoved = p.recentlyRemoved[:0]

	for {
		iter, found := p.ts.GetIterFirst()
		if iter == nil || found == false {
			break
		}
		pi, _ := p.ts.GetPath(iter)
		if pi == nil {
			break
		}
		p.tv.SetCursor(pi, nil, false)
		_, idx, subidx, err := p.getSelectedRule()
		if err != nil {
			break
		}
		p.removeSelectedRule(idx, subidx)
	}
}

func (p *Prompt) makeDecision(rule string, scope int, guid string) error {
	return p.app.Dbus.answerPrompt(uint32(scope), rule, guid)
}

func (p *Prompt) buttonAction(guid string, rr *sgfw.DbusRule) {
	p.promptLock.Lock()
	rule, idx, subidx, err := p.getSelectedRule()
	if err != nil {
		p.promptLock.Unlock()
		warnDialog(&p.app.win.Window, "Error occurred processing request: %s", err.Error())
		return
	}

	tk := strings.Split(rr.Target, ":")
	// Overlay the rules
	rule.Scope = int(rr.Mode)
	//rule.Path = urule.Path
	rule.Port, _ = strconv.Atoi(tk[1])
	rule.Target = tk[0]
	rule.Proto = rr.Proto
	rule.UID = int(rr.UID)
	rule.GID = int(rr.GID)
	// rule.Uname = urule.Uname
	// rule.Gname = urule.Gname

	fmt.Println("rule = ", rule)

	action := sgfw.RuleActionString[sgfw.RuleAction(rr.Verb)]
	rulestr := action

	proto := rule.Proto
	if proto == "any" || proto == "" {
		proto = "*"
	}
	rulestr += "|" + proto + ":" + rule.Target + ":" + strconv.Itoa(rule.Port)
	rulestr += "|" + sgfw.RuleModeString[sgfw.RuleMode(rule.Scope)]
	rulestr += "|" + strconv.Itoa(rule.UID) + ":" + strconv.Itoa(rule.GID)
	if rule.Sandbox != "" {
		rulestr += "|" + rule.Sandbox
	}
	fmt.Println("RULESTR = ", rulestr)
	p.makeDecision(rulestr, int(rule.Scope), guid)
	err = p.removeSelectedRule(idx, subidx)
	p.addRecentlyRemoved(guid)
	p.promptLock.Unlock()
	if err != nil {
		warnDialog(&p.app.win.Window, "Error setting new rule: %s", err.Error())
	}
}
