package sgfw

import (
	"strings"
)

const (
	STR_REDACTED = "[redacted]"
	STR_UNKNOWN  = "[uknown]"
)

type RuleAction uint16

const (
	RULE_ACTION_DENY RuleAction = iota
	RULE_ACTION_ALLOW
)

var RuleActionString = map[RuleAction]string{
	RULE_ACTION_DENY:  "DENY",
	RULE_ACTION_ALLOW: "ALLOW",
}

var RuleActionValue = map[string]RuleAction{
	"DENY":  RULE_ACTION_DENY,
	"ALLOW": RULE_ACTION_ALLOW,
}

type RuleMode uint16

const (
	RULE_MODE_SESSION RuleMode = iota
	RULE_MODE_PERMANENT
	RULE_MODE_SYSTEM
)

var RuleModeString = map[RuleMode]string{
	RULE_MODE_SESSION:   "SESSION",
	RULE_MODE_PERMANENT: "PERMANENT",
	RULE_MODE_SYSTEM:    "SYSTEM",
}

var RuleModeValue = map[string]RuleMode{
	"SESSION":   RULE_MODE_SESSION,
	"PERMANENT": RULE_MODE_PERMANENT,
	"SYSTEM":    RULE_MODE_SYSTEM,
}

type FilterScope uint16

const (
	APPLY_ONCE FilterScope = iota
	APPLY_SESSION
	APPLY_FOREVER
)

var FilterScopeString = map[FilterScope]string{
	APPLY_ONCE:    "ONCE",
	APPLY_SESSION: "SESSION",
	APPLY_FOREVER: "FOREVER",
}

var FilterScopeValue = map[string]FilterScope{
	"ONCE":    APPLY_ONCE,
	"SESSION": APPLY_SESSION,
	"FOREVER": APPLY_FOREVER,
}

func GetFilterScopeString(scope FilterScope) string {
	if val, ok := FilterScopeString[scope]; ok {
		return val
	}
	return FilterScopeString[APPLY_SESSION]
}

func GetFilterScopeValue(scope string) FilterScope {
	scope = strings.ToUpper(scope)
	if val, ok := FilterScopeValue[scope]; ok {
		return val
	}
	return APPLY_SESSION
}

type FilterResult uint16

const (
	FILTER_DENY FilterResult = iota
	FILTER_ALLOW
	FILTER_PROMPT
)

var FilterResultString = map[FilterResult]string{
	FILTER_DENY:   "DENY",
	FILTER_ALLOW:  "ALLOW",
	FILTER_PROMPT: "PROMPT",
}

var FilterResultValue = map[string]FilterResult{
	"DENY":   FILTER_DENY,
	"ALLOW":  FILTER_ALLOW,
	"PROMPT": FILTER_PROMPT,
}

type DbusRule struct {
	ID     uint32
	App    string
	Path   string
	Verb   uint16
	Target string
	Mode   uint16
}
