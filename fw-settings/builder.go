package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"github.com/subgraph/fw-daemon/fw-settings/definitions"
)

const (
	defsFolder   = "definitions"
	xmlExtension = ".xml"
)

func getDefinitionWithFileFallback(uiName string) string {
	// this makes sure a missing definition wont break only when the app is released
	uiDef := getDefinition(uiName)

	fileName := filepath.Join(defsFolder, uiName+xmlExtension)
	if fileNotFound(fileName) {
		return uiDef.String()
	}

	return readFile(fileName)
}

// This must be called from the UI thread - otherwise bad things will happen sooner or later
func builderForDefinition(uiName string) *gtk.Builder {
	// assertInUIThread()

	template := getDefinitionWithFileFallback(uiName)

	maj := gtk.GetMajorVersion()
	min := gtk.GetMinorVersion()

	if (maj == 3) && (min < 20) {
		fmt.Fprintf(os.Stderr,
			"Attempting runtime work-around for older versions of libgtk-3...\n")
		dep_re := regexp.MustCompile(`<\s?property\s+name\s?=\s?"icon_size"\s?>.+<\s?/property\s?>`)
		template = dep_re.ReplaceAllString(template, ``)

		dep_re2 := regexp.MustCompile(`version\s?=\s?"3.20"`)
		template = dep_re2.ReplaceAllString(template, `version="3.18"`)
	}

	builder, err := gtk.BuilderNew()
	if err != nil {
		//We cant recover from this
		panic(err)
	}

	err = builder.AddFromString(template)
	if err != nil {
		//This is a programming error
		panic(fmt.Sprintf("gui: failed load %s: %s\n", uiName, err.Error()))
	}

	return builder
}

func fileNotFound(fileName string) bool {
	_, fnf := os.Stat(fileName)
	return os.IsNotExist(fnf)
}

func readFile(fileName string) string {
	file, _ := os.Open(fileName)
	reader := bufio.NewScanner(file)
	var content string
	for reader.Scan() {
		content = content + reader.Text()
	}
	file.Close()
	return content
}

func getDefinition(uiName string) fmt.Stringer {
	def, ok := definitions.Get(uiName)
	if !ok {
		panic(fmt.Sprintf("No definition found for %s", uiName))
	}

	return def
}

type builder struct {
	*gtk.Builder
}

func newBuilder(uiName string) *builder {
	return &builder{builderForDefinition(uiName)}
}

func (b *builder) getItem(name string, target interface{}) {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Ptr {
		panic("builder.getItem() target argument must be a pointer")
	}
	elem := v.Elem()
	elem.Set(reflect.ValueOf(b.get(name)))
}

func (b *builder) getItems(args ...interface{}) {
	for len(args) >= 2 {
		name, ok := args[0].(string)
		if !ok {
			panic("string argument expected in builder.getItems()")
		}
		b.getItem(name, args[1])
		args = args[2:]
	}
}

func (b *builder) get(name string) glib.IObject {
	obj, err := b.GetObject(name)
	if err != nil {
		panic("builder.GetObject() failed: " + err.Error())
	}
	return obj
}
