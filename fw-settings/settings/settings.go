package settings

import (
	"os"

	"github.com/subgraph/fw-daemon/fw-settings/settings/definitions"
	"github.com/gotk3/gotk3/glib"
)

var cachedSchema *glib.SettingsSchemaSource

func getSchemaSource() *glib.SettingsSchemaSource {
	if cachedSchema == nil {
		dir := definitions.SchemaInTempDir()
		defer os.Remove(dir)
		cachedSchema = glib.SettingsSchemaSourceNewFromDirectory(dir, nil, true)
	}

	return cachedSchema
}

func getSchema() *glib.SettingsSchema {
	return getSchemaSource().Lookup("com.subgraph.Firewall.Settings", false)
}

func getDefaultSettings() *glib.Settings {
	return glib.SettingsNewFull(getSchema(), nil, "/com/subgraph/firewall/settings/")
}

type Settings struct {
	def, spec *glib.Settings
}

func Init() *Settings {
	s := &Settings{}
	s.def = getDefaultSettings()
	return s
}

func (s *Settings) settingsForGet(name string) *glib.Settings {
	if s.spec != nil {
		return s.spec
	}
	return s.def
}

func (s *Settings) settingsForSet() *glib.Settings {
	if s.spec != nil {
		return s.spec
	}
	return s.def
}

func (s *Settings) getBooleanSetting(name string) bool {
	return s.settingsForGet(name).GetBoolean(name)
}

func (s *Settings) setBooleanSetting(name string, val bool) {
	sets := s.settingsForSet()
	sets.SetBoolean(name, val)
}

func (s *Settings) getIntegerSetting(name string) int {
	return s.settingsForGet(name).GetInt(name)
}

func (s *Settings) setIntegerSetting(name string, val int) {
	sets := s.settingsForSet()
	sets.SetInt(name, val)
}


func (s *Settings) getUIntegerSetting(name string) uint {
	return s.settingsForGet(name).GetUInt(name)
}

func (s *Settings) setUIntegerSetting(name string, val uint) {
	sets := s.settingsForSet()
	sets.SetUInt(name, val)
}

func (s *Settings) getStringSetting(name string) string {
	return s.settingsForGet(name).GetString(name)
}

func (s *Settings) setStringSetting(name string, val string) {
	sets := s.settingsForSet()
	sets.SetString(name, val)
}

func (s *Settings) GetWindowHeight() uint {
	return s.getUIntegerSetting("window-height")
}

func (s *Settings) SetWindowHeight(v uint) {
	s.setUIntegerSetting("window-height", v)
}

func (s *Settings) GetWindowWidth() uint {
	return s.getUIntegerSetting("window-width")
}

func (s *Settings) SetWindowWidth(v uint) {
	s.setUIntegerSetting("window-width", v)
}

func (s *Settings) GetWindowTop() uint {
	return s.getUIntegerSetting("window-top")
}

func (s *Settings) SetWindowTop(v uint) {
	s.setUIntegerSetting("window-top", v)
}

func (s *Settings) GetWindowLeft() uint {
	return s.getUIntegerSetting("window-left")
}

func (s *Settings) SetWindowLeft(v uint) {
	s.setUIntegerSetting("window-left", v)
}

func (s *Settings) GetToplevelPrompt() bool {
	return s.getBooleanSetting("prompt-toplevel")
}

func (s *Settings) SetToplevelPrompt(v bool) {
	s.setBooleanSetting("prompt-toplevel", v)
}
