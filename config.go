// TODO: Check permissions on file
// TODO: Create dir if needed
// TODO: Dont' fail hard on failed read
package main

import (
	"bufio"
	"io/ioutil"
	"os"

	"github.com/naoina/toml"
	"github.com/op/go-logging"
)

const (
	configDefaultPath string = "/etc/sgfw/sgfw.conf"
)

type FirewallConfigs struct {
	LogLevel        string
	LoggingLevel    logging.Level `toml:"-"`
	LogRedact       bool
	PromptExpanded  bool
	PromptExpert    bool
	DefaultAction   string
	DefaultActionId int32 `toml:"-"`
}

var FirewallConfig FirewallConfigs

func readConfig() {
	f, err := os.Open(configDefaultPath)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	defer f.Close()
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	FirewallConfig = FirewallConfigs{
		LogLevel:        "NOTICE",
		LoggingLevel:    logging.NOTICE,
		LogRedact:       false,
		PromptExpanded:  false,
		PromptExpert:    false,
		DefaultAction:   "SESSION",
		DefaultActionId: 1,
	}

	if err := toml.Unmarshal(buf, &FirewallConfig); err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	FirewallConfig.LoggingLevel, _ = logging.LogLevel(FirewallConfig.LogLevel)
	FirewallConfig.DefaultActionId = valueScope(FirewallConfig.DefaultAction)
}

func writeConfig() {
	FirewallConfig.LogLevel = FirewallConfig.LoggingLevel.String()
	FirewallConfig.DefaultAction = printScope(FirewallConfig.DefaultActionId)

	f, err := os.Create(configDefaultPath)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	cw := toml.NewEncoder(w)
	if err := cw.Encode(FirewallConfig); err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	w.Flush()
}
