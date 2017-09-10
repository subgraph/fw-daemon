package sgfw

import (
	"github.com/subgraph/ozipc"
)

type ListSandboxesMsg struct {
	_ string "ListSandboxes"
}

type SandboxInfo struct {
	Id      int
	Address string
	Profile string
	Mounts  []string
	InitPid int
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
}
