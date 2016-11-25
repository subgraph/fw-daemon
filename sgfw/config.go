package main

import (
	"bufio"
	"io/ioutil"
	"os"
	"path"

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

func _readConfig(file string) []byte {
	f, err := os.Open(configDefaultPath)
	if err != nil {
		log.Warning(err.Error())
		return []byte{}
	}
	defer f.Close()
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		log.Warning(err.Error())
		return []byte{}
	}

	return buf
}

func readConfig() {
	buf := _readConfig(configDefaultPath)

	FirewallConfig = FirewallConfigs{
		LogLevel:        "NOTICE",
		LoggingLevel:    logging.NOTICE,
		LogRedact:       false,
		PromptExpanded:  false,
		PromptExpert:    false,
		DefaultAction:   "SESSION",
		DefaultActionId: 1,
	}

	if len(buf) > 0 {
		if err := toml.Unmarshal(buf, &FirewallConfig); err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	}
	FirewallConfig.LoggingLevel, _ = logging.LogLevel(FirewallConfig.LogLevel)
	FirewallConfig.DefaultActionId = valueScope(FirewallConfig.DefaultAction)
}

func writeConfig() {
	FirewallConfig.LogLevel = FirewallConfig.LoggingLevel.String()
	FirewallConfig.DefaultAction = printScope(FirewallConfig.DefaultActionId)

	if _, err := os.Stat(path.Dir(configDefaultPath)); err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(path.Dir(configDefaultPath), 0755); err != nil {
			log.Error(err.Error())
			//os.Exit(1)
			return
		}
	}

	f, err := os.Create(configDefaultPath)
	if err != nil {
		log.Error(err.Error())
		//os.Exit(1)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	cw := toml.NewEncoder(w)
	if err := cw.Encode(FirewallConfig); err != nil {
		log.Error(err.Error())
		//os.Exit(1)
		return
	}
	w.Flush()
}
