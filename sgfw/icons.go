package sgfw

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

type DesktopEntry struct {
	icon string
	name string
}

var entryMap = map[string]*DesktopEntry{}
var initialized = false

func entryForPath(p string) *DesktopEntry {
	if !initialized {
		initIcons()
	}
	entry, ok := entryMap[path.Base(p)]
	if ok {
		return entry
	}
	return entryMap[p]
}

func initIcons() {
	if initialized {
		return
	}
	path := "/usr/share/applications"
	dir, err := os.Open(path)
	if err != nil {
		log.Warningf("Failed to open %s for reading: %v", path, err)
		return
	}
	names, err := dir.Readdirnames(0)
	if err != nil {
		log.Warningf("Could not read directory %s: %v", path, err)
		return
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".desktop") {
			loadDesktopFile(fmt.Sprintf("%s/%s", path, n))
		}
	}
	initialized = true
}

func loadDesktopFile(path string) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warningf("Error reading %s: %v", path, err)
		return
	}
	exec := ""
	icon := ""
	name := ""
	inDE := false

	for _, line := range strings.Split(string(bs), "\n") {
		if strings.Contains(line, "[Desktop Entry]") {
			inDE = true
		} else if len(line) > 0 && line[0] == '[' {
			inDE = false
		}
		if inDE && strings.HasPrefix(line, "Exec=") {
			fields := strings.Fields(line[5:])
			if len(fields) > 0 {
				exec = fields[0]
			}
		}
		if inDE && strings.HasPrefix(line, "Icon=") {
			icon = line[5:]
		}
		if inDE && strings.HasPrefix(line, "Name=") {
			name = line[5:]
		}
	}
	if exec != "" && icon != "" {
		entryMap[exec] = &DesktopEntry{
			icon: icon,
			name: name,
		}
	}
}
