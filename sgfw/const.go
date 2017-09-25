package sgfw

import (
	"strings"
)

// Static strings for various usage
const (
	STR_REDACTED = "[redacted]"
	STR_UNKNOWN  = "[uknown]"
)

//RuleAction is the action to apply to a rule
type RuleAction uint16

const (
	RULE_ACTION_DENY RuleAction = iota
	RULE_ACTION_ALLOW
	RULE_ACTION_ALLOW_TLSONLY
)

// RuleActionString is used to get a string from an action id
var RuleActionString = map[RuleAction]string{
	RULE_ACTION_DENY:          "DENY",
	RULE_ACTION_ALLOW:         "ALLOW",
	RULE_ACTION_ALLOW_TLSONLY: "ALLOW_TLSONLY",
}

// RuleActionValue is used to get an action id using the action string
var RuleActionValue = map[string]RuleAction{
	RuleActionString[RULE_ACTION_DENY]:          RULE_ACTION_DENY,
	RuleActionString[RULE_ACTION_ALLOW]:         RULE_ACTION_ALLOW,
	RuleActionString[RULE_ACTION_ALLOW_TLSONLY]: RULE_ACTION_ALLOW_TLSONLY,
}

//RuleMode contains the time scope of a rule
type RuleMode uint16

const (
	RULE_MODE_SESSION RuleMode = iota
	RULE_MODE_PROCESS
	RULE_MODE_PERMANENT
	RULE_MODE_SYSTEM
)

// RuleModeString is used to get a rule mode string from its id
var RuleModeString = map[RuleMode]string{
	RULE_MODE_SESSION:   "SESSION",
	RULE_MODE_PROCESS:   "PROCESS",
	RULE_MODE_PERMANENT: "PERMANENT",
	RULE_MODE_SYSTEM:    "SYSTEM",
}

// RuleModeValue converts a mode string to its id
var RuleModeValue = map[string]RuleMode{
	RuleModeString[RULE_MODE_SESSION]:   RULE_MODE_SESSION,
	RuleModeString[RULE_MODE_PROCESS]:   RULE_MODE_PROCESS,
	RuleModeString[RULE_MODE_PERMANENT]: RULE_MODE_PERMANENT,
	RuleModeString[RULE_MODE_SYSTEM]:    RULE_MODE_SYSTEM,
}

//FilterScope contains a filter's time scope
type FilterScope uint16

const (
	APPLY_ONCE FilterScope = iota
	APPLY_SESSION
	APPLY_PROCESS
	APPLY_FOREVER
)

// FilterScopeString converts a filter scope ID to its string
var FilterScopeString = map[FilterScope]string{
	APPLY_ONCE:    "ONCE",
	APPLY_SESSION: "SESSION",
	APPLY_PROCESS: "PROCESS",
	APPLY_FOREVER: "FOREVER",
}

// FilterScopeString converts a filter scope string to its ID
var FilterScopeValue = map[string]FilterScope{
	FilterScopeString[APPLY_ONCE]:    APPLY_ONCE,
	FilterScopeString[APPLY_SESSION]: APPLY_SESSION,
	FilterScopeString[APPLY_PROCESS]: APPLY_PROCESS,
	FilterScopeString[APPLY_FOREVER]: APPLY_FOREVER,
}

// GetFilterScopeString is used to safely return a filter scope string
func GetFilterScopeString(scope FilterScope) string {
	if val, ok := FilterScopeString[scope]; ok {
		return val
	}
	return FilterScopeString[APPLY_SESSION]
}

// GetFilterScopeValue is used to safely return a filter scope ID
func GetFilterScopeValue(scope string) FilterScope {
	scope = strings.ToUpper(scope)
	if val, ok := FilterScopeValue[scope]; ok {
		return val
	}
	return APPLY_SESSION
}

//FilterResult contains the filtering resulting action
type FilterResult uint16

const (
	FILTER_DENY FilterResult = iota
	FILTER_ALLOW
	FILTER_PROMPT
	FILTER_ALLOW_TLSONLY
)

// FilterResultString converts a filter value ID to its string
var FilterResultString = map[FilterResult]string{
	FILTER_DENY:          "DENY",
	FILTER_ALLOW:         "ALLOW",
	FILTER_PROMPT:        "PROMPT",
	FILTER_ALLOW_TLSONLY: "ALLOW_TLSONLY",
}

// FilterResultValue converts a filter value string to its ID
var FilterResultValue = map[string]FilterResult{
	FilterResultString[FILTER_DENY]:          FILTER_DENY,
	FilterResultString[FILTER_ALLOW]:         FILTER_ALLOW,
	FilterResultString[FILTER_PROMPT]:        FILTER_PROMPT,
	FilterResultString[FILTER_ALLOW_TLSONLY]: FILTER_ALLOW_TLSONLY,
}

// DbusRule struct of the rule passed to the dbus interface
type DbusRule struct {
	ID      uint32
	Net     string
	Origin  string
	Proto   string
	Pid     uint32
	Privs   string
	App     string
	Path    string
	Verb    uint16
	Target  string
	Mode    uint16
	Sandbox string
}

/*const (
	OZ_FWRULE_WHITELIST = iota
	OZ_FWRULE_BLACKLIST
	OZ_FWRULE_NONE
) */
