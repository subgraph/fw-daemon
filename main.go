package main

import (
	"github.com/subgraph/fw-daemon/sgfw"
)

func init() {
	sgfw.InitVirtual()
	sgfw.InitIPC()
	sgfw.InitPrompt()
}

func main() {
	sgfw.Main()
}
