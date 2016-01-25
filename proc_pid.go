package main
import (
	"os"
	"strconv"
	"fmt"
	"strings"
	"path"
	"io/ioutil"
)


type ProcInfo struct {
	pid     int
	loaded bool
	exePath string
	cmdLine string
}


var cacheMap = make(map[uint64]*ProcInfo)

func pidCacheLookup(inode uint64) *ProcInfo {
	pi,ok := cacheMap[inode]
	if ok {
		return pi
	}
	pidCacheReload()
	return cacheMap[inode]
}

func pidCacheReload() {
	for _, n := range readdir("/proc") {
		pid := toPid(n)
		if pid != 0 {
			scrapePid(pid)
		}
	}
}

func toPid(name string) int {
	pid, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		return 0
	}
	fdpath := fmt.Sprintf("/proc/%d/fd", pid)
	fi,err := os.Stat(fdpath)
	if err != nil {
		return 0
	}
	if !fi.IsDir() {
		return 0
	}
	return (int)(pid)
}

func scrapePid(pid int) {
	fdpath := fmt.Sprintf("/proc/%d/fd", pid)
	for _, n := range readdir(fdpath) {
		if link, err := os.Readlink(path.Join(fdpath, n)); err != nil {
			log.Warning("Error reading link %s: %v", n, err)
		} else {
			extractSocket(link, pid)
		}
	}
}

func extractSocket(name string, pid int) {
	if !strings.HasPrefix(name, "socket:[") || !strings.HasSuffix(name, "]") {
		return
	}
	val := name[8:len(name)-1]
	inode,err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		log.Warning("Error parsing inode value from %s: %v", name, err)
		return
	}
	cacheAddPid(inode, pid)
}

func cacheAddPid(inode uint64, pid int) {
	pi,ok := cacheMap[inode]
	if ok && pi.pid == pid {
		return
	}
	cacheMap[inode] = &ProcInfo{ pid: pid }
}

func readdir(dir string) []string {
	d,err := os.Open(dir)
	if err != nil {
		log.Warning("Error opening directory %s: %v", dir, err)
		return nil
	}
	defer d.Close()
	names, err := d.Readdirnames(0)
	if err != nil {
		log.Warning("Error reading directory names from %s: %v", dir, err)
		return nil
	}
	return names
}

func (pi *ProcInfo) loadProcessInfo() bool {
	if pi.loaded {
		return true
	}

	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pi.pid))
	if err != nil {
		log.Warning("Error reading exe link for pid %d: %v", pi.pid, err)
		return false
	}
	bs, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pi.pid))
	if err != nil {
		log.Warning("Error reading cmdline for pid %d: %v", pi.pid, err)
		return false
	}
	for i, b := range bs {
		if b == 0 {
			bs[i] = byte(' ')
		}
	}

	finfo, err := os.Stat(fmt.Sprintf("/proc/%d", pi.pid))
	if err != nil {
		log.Warning("Could not stat /proc/%d: %v", pi.pid, err)
		return false
	}
	finfo.Sys()
	pi.exePath = exePath
	pi.cmdLine = string(bs)
	pi.loaded = true
	return true
}
