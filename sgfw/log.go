package sgfw

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/op/go-logging"
)

// Log level conversion map
var LevelToID = map[int32]string{
	int32(logging.ERROR):   "error",
	int32(logging.WARNING): "warning",
	int32(logging.NOTICE):  "notice",
	int32(logging.INFO):    "info",
	int32(logging.DEBUG):   "debug",
}

// Log level string conversion
var IDToLevel = func() map[string]int32 {
	m := make(map[string]int32)
	for k, v := range LevelToID {
		m[v] = k
	}
	return m
}()

var log = logging.MustGetLogger("sgfw")

var logFormat = logging.MustStringFormatter(
	"%{level:.4s} %{id:03x} %{message}",
)
var ttyFormat = logging.MustStringFormatter(
	"%{color}%{time:15:04:05} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

const ioctlReadTermios = 0x5401

func isTerminal(fd int) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), ioctlReadTermios, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}

func setupLoggerBackend(lvl logging.Level) logging.LeveledBackend {
	format := logFormat
	if isTerminal(int(os.Stderr.Fd())) {
		format = ttyFormat
	}
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	leveler.SetLevel(lvl, "sgfw")
	return leveler
}
