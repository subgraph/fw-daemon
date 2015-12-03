package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const iptablesRule = "-t mangle -%c OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass"
const dnsRule = "-%c INPUT --protocol udp -m multiport --source-ports 53 -j NFQUEUE --queue-num 0 --queue-bypass"

func setupIPTables() {
	removeIPTRules(dnsRule, iptablesRule)
	addIPTRules(iptablesRule, dnsRule)
}

func removeIPTRules(rules ...string) {
	for _, r := range rules {
		iptables('D', r)
	}
}

func addIPTRules(rules ...string) {
	for _, r := range rules {
		iptables('I', r)
	}
}

func iptables(verb rune, rule string) {

	iptablesPath, err := exec.LookPath("iptables")
	if err != nil {
		log.Warning("Could not find iptables binary in path")
		os.Exit(1)
	}

	argLine := fmt.Sprintf(rule, verb)
	args := strings.Fields(argLine)
	fmt.Println(iptablesPath, argLine)
	cmd := exec.Command(iptablesPath, args...)
	out, err := cmd.CombinedOutput()
	fmt.Fprintf(os.Stderr, string(out))
	_, exitErr := err.(*exec.ExitError)
	if err != nil && !exitErr {
		log.Warning("Error reading output: %v", err)
	}
}
