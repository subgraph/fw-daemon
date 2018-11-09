package sgfw

import (
	"github.com/subgraph/ozipc"
	"strings"
	"fmt"
	"os"
	"bufio"
	"strconv"
	"github.com/godbus/dbus"
)

type ListSandboxesMsg struct {
	_ string "ListSandboxes"
}

type SandboxInfo struct {
	Id      int
	Address string
	Name    string
	Profile string
	Mounts  []string
	InitPid int
	Pid string
}

type ListSandboxesResp struct {
	Sandboxes []SandboxInfo "ListSandboxesResp"
}

const socketPath = "@oz-control"

var ozCtrlFactory = ipc.NewMsgFactory(
	new(ListSandboxesMsg),
	new(ListSandboxesResp),
)

func getSandboxes() ([]SandboxInfo, error) {

	f, err := os.Open("/run/realms/network-clear")
	if err != nil {
		fmt.Print("no realms network file")
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	var sboxes []SandboxInfo
	i := 0;
	var db,_ = dbus.SystemBus()
	obj := db.Object("com.subgraph.realms", "/")
	for scanner.Scan() {
		var leaderpid string
		s := strings.Split(scanner.Text(), ":")
		obj.Call("com.subgraph.realms.Manager.LeaderPidFromIP", 0, s[1]).Store(&leaderpid)
		p, _ := strconv.Atoi(leaderpid)
		sboxes = append(sboxes,SandboxInfo{Id: i, Name: s[0], Address: s[1], InitPid: p})
		fmt.Print(s[0], s[1], leaderpid)
		i++;
	}


	/*
	c, err := ipc.Connect(socketPath, ozCtrlFactory, nil)
	if err != nil {
		return nil, err
	}

	defer c.Close()
	rr, err := c.ExchangeMsg(&ListSandboxesMsg{})
	if err != nil {
		return nil, err
	}

	resp := <-rr.Chan()
	rr.Done()
	sboxes := resp.Body.(*ListSandboxesResp)
	return sboxes.Sandboxes, nil
	*/
	return sboxes, nil
}
