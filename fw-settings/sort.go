// +build go1.8

package main

import (
	"sort"

	"github.com/subgraph/fw-daemon/sgfw"
)

func (rl *ruleList) sortRules(rules []sgfw.DbusRule) []sgfw.DbusRule {
	sort.SliceStable(rules, func(i, j int) bool {
		//sgfw.RuleActionString[sgfw.RuleAction(rules[i].Verb)] 
		//sgfw.RuleActionString[sgfw.RuleAction(rules[j].Verb)] 
		in := rules[i].Sandbox + rules[i].App + rules[i].Target
		jn := rules[j].Sandbox + rules[j].App + rules[j].Target
		order := []string{in,jn}
		sort.Strings(order)
		if rules[i].App == rules[j].App && rules[i].Sandbox == rules[j].Sandbox {
			if sgfw.RuleAction(rules[i].Verb) == sgfw.RULE_ACTION_DENY || sgfw.RuleAction(rules[j].Verb) == sgfw.RULE_ACTION_DENY {
				if rules[i].Verb != rules[j].Verb {
					return (sgfw.RuleAction(rules[i].Verb) == sgfw.RULE_ACTION_DENY)
				}
			}
		}
		return (order[0] == in)
	})
	return rules
}
