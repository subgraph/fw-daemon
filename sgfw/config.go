package sgfw

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
	DefaultActionID FilterScope `toml:"-"`
}

var FirewallConfig FirewallConfigs

func _readConfig(file string) []byte {
	envFile := os.Getenv("SGFW_CONF")

        if envFile != "" {
		file = envFile
	}

	f, err := os.Open(file)
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
		DefaultActionID: 1,
	}

	if len(buf) > 0 {
		if err := toml.Unmarshal(buf, &FirewallConfig); err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	}
	FirewallConfig.LoggingLevel, _ = logging.LogLevel(FirewallConfig.LogLevel)
	FirewallConfig.DefaultActionID = GetFilterScopeValue(FirewallConfig.DefaultAction)
}

func writeConfig() {
	FirewallConfig.LogLevel = FirewallConfig.LoggingLevel.String()
	FirewallConfig.DefaultAction = GetFilterScopeString(FirewallConfig.DefaultActionID)

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
