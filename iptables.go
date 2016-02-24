package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const iptablesRule = "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass"
const dnsRule = "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass"
const blockRule = "OUTPUT --protocol tcp -m mark --mark 1 -j REJECT"

func setupIPTables() {
	addIPTRules(iptablesRule, dnsRule, blockRule)
}

func addIPTRules(rules ...string) {
	for _, r := range rules {
		if iptables('C', r) {
			log.Info("IPTables rule already present: %s", r)
		} else {
			log.Info("Installing IPTables rule: %s", r)
			iptables('I', r)
		}
	}
}

func iptables(verb rune, rule string) bool {
	iptablesPath, err := exec.LookPath("iptables")
	if err != nil {
		log.Warning("Could not find iptables binary in path")
		os.Exit(1)
	}
	argLine := fmt.Sprintf("-%c %s", verb, rule)
	args := strings.Fields(argLine)
	cmd := exec.Command(iptablesPath, args...)
	_, err = cmd.CombinedOutput()
	_, exitErr := err.(*exec.ExitError)
	if err != nil && !exitErr {
		log.Warning("Error running iptables: %v", err)
	}
	return !exitErr
}
