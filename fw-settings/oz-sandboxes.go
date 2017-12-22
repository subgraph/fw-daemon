package main

import (
	"fmt"
	"os"

	"github.com/subgraph/oz"
)

var ozProfiles oz.Profiles

func init() {
	c, err := oz.LoadConfig(oz.DefaultConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read oz config...")
		os.Exit(1)
	}
	p, err := oz.LoadProfiles(c.ProfileDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read oz profiles...")
		os.Exit(1)
	}
	ozProfiles = p
}

func (fa *fwApp) initOZProfiles() {
	for _, p := range ozProfiles {
		// XXX: This actually should match against sgfw's opened sockets
		switch {
		case string(p.Networking.Nettype) == "host":
			fallthrough
		case len(p.Networking.Sockets) == 0:
			continue
		default:
			fa.ozProfiles = append(fa.ozProfiles, p.Name)
		}
	}
}
