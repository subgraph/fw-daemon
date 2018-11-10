package sgfw

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const iptablesRule = "OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass"
const realmsRule = "FORWARD -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass"
const dnsRule2 = "FORWARD --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass"
const dnsRule = "INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass"

//const logRule = "OUTPUT --protocol tcp -m mark --mark 1 -j LOG"
const blockRule = "OUTPUT --protocol tcp -m mark --mark 1 -j REJECT"
const blockRule2 = "FORWARD --protocol tcp -m mark --mark 1 -j REJECT"

func setupIPTables() {
	//	addIPTRules(iptablesRule, dnsRule, logRule, blockRule)
//	addIPTRules(iptablesRule, realmsRule, dnsRule, dnsRule2, blockRule,blockRule2)
	//addIPTRules(iptablesRule, realmsRule, dnsRule, blockRule)
	addIPTRules(iptablesRule, realmsRule, dnsRule, dnsRule2, blockRule,blockRule2)
}

func addIPTRules(rules ...string) {
	for _, r := range rules {
		if iptables('C', r) {
			log.Infof("IPTables rule already present: %s", r)
		} else {
			log.Infof("Installing IPTables rule: %s", r)
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
		log.Warningf("Error running iptables: %v", err)
	}
	return !exitErr
}
