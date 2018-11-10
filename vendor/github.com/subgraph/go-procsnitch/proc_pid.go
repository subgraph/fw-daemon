package procsnitch

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	//"github.com/godbus/dbus"
)

// Info is a struct containing the result of a socket proc query
type Info struct {
	UID           int
	GID           int
	Pid           int
	ParentPid     int
	loaded        bool
	ExePath       string
	CmdLine       string
	FirstArg      string
	ParentCmdLine string
	ParentExePath string
	Realm         string
	Sandbox       string
	LeaderPid     string
	Inode         uint64
	FD            int
}

type pidCache struct {
	cacheMap map[uint64]*Info
	lock     sync.Mutex
}

func (pc *pidCache) lookup(inode uint64) *Info {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	pi, ok := pc.cacheMap[inode]
	if ok && pi.loadProcessInfo() {
		return pi
	}
	pc.cacheMap = loadCache()
	pi, ok = pc.cacheMap[inode]
	if ok && pi.loadProcessInfo() {
		return pi
	}
	return nil
}

func loadCache() map[uint64]*Info {
	cmap := make(map[uint64]*Info)
	for _, n := range readdir("/proc") {
		pid := toPid(n)
		if pid != 0 {
			inodes, fds := inodesFromPid(pid)
			for iind, inode := range inodes {
				pinfo := &Info{Inode: inode, Pid: pid, FD: fds[iind]}
				cmap[inode] = pinfo
			}

		}
	}
	return cmap
}

func toPid(name string) int {
	pid, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		return 0
	}
	fdpath := fmt.Sprintf("/proc/%d/fd", pid)
	fi, err := os.Stat(fdpath)
	if err != nil {
		return 0
	}
	if !fi.IsDir() {
		return 0
	}
	return (int)(pid)
}

func inodesFromPid(pid int) ([]uint64, []int) {
	var inodes []uint64
	var fds []int
	fdpath := fmt.Sprintf("/proc/%d/fd", pid)
	for _, n := range readdir(fdpath) {
		if link, err := os.Readlink(path.Join(fdpath, n)); err != nil {
			if !os.IsNotExist(err) {
				log.Warningf("Error reading link %s: %v", n, err)
			}
		} else {
			fd, err := strconv.Atoi(n)
			if err != nil {
				log.Warningf("Error retrieving fd associated with pid %v: %v", pid, err)
				fd = -1
			}

			if inode := extractSocket(link); inode > 0 {
				inodes = append(inodes, inode)
				fds = append(fds, fd)
			}
		}
	}
	return inodes, fds
}

func extractSocket(name string) uint64 {
	if !strings.HasPrefix(name, "socket:[") || !strings.HasSuffix(name, "]") {
		return 0
	}
	val := name[8 : len(name)-1]
	inode, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		log.Warningf("Error parsing inode value from %s: %v", name, err)
		return 0
	}
	return inode
}

func readdir(dir string) []string {
	d, err := os.Open(dir)
	if err != nil {
		log.Warningf("Error opening directory %s: %v", dir, err)
		return nil
	}
	defer d.Close()
	names, err := d.Readdirnames(0)
	if err != nil {
		log.Warningf("Error reading directory names from %s: %v", dir, err)
		return nil
	}
	return names
}

func (pi *Info) loadProcessInfo() bool {
	if pi.loaded {
		return true
	}
	leaderpid := ""
	realm := "unknown"
	//conn, _ := dbus.SystemBus()
	//obj := conn.Object("com.subgraph.realms", "/")
	//obj.Call("com.subgraph.realms.Manager.RealmFromContainerPid", 0, fmt.Sprintf("%d",pi.Pid)).Store(&realm)
	//obj.Call("com.subgraph.realms.Manager.LeaderPidFromRealm", 0, realm).Store(&leaderpid)
	pi.LeaderPid = leaderpid
	prefix := ""
	if leaderpid != "" {
		prefix = fmt.Sprintf("/proc/%s/root",leaderpid)
	}
	prefix = "" 
	exePath, err := os.Readlink(fmt.Sprintf("%s/proc/%d/exe", prefix, pi.Pid))
	if err != nil {
		log.Warningf("Error reading exe link for pid %d: %v", pi.Pid, err)
		return false
	}
	bcs, err := ioutil.ReadFile(fmt.Sprintf("%s/proc/%d/cmdline", prefix, pi.Pid))
	if err != nil {
		log.Warningf("Error reading cmdline for pid %d: %v", pi.Pid, err)
		return false
	}
	for i, b := range bcs {
		if b == 0 {
			bcs[i] = byte(' ')
		}
	}

	bs, err := ioutil.ReadFile(fmt.Sprintf("%s/proc/%d/stat", prefix, pi.Pid))
	if err != nil {
		log.Warningf("Error reading cmdline for pid %d: %v", pi.Pid, err)
		return false
	}
	fs := strings.Fields(string(bs))
	if len(fs) < 50 {
		log.Warningf("Unable to parse stat for pid %d: ", pi.Pid)
		return false
	}
	ppid := toPid(fs[3])

	pexePath, err := os.Readlink(fmt.Sprintf("%s/proc/%d/exe", prefix, ppid))
	if err != nil {
		log.Warningf("Error reading exe link for parent pid %d: %v", ppid, err)
		return false
	}
	pbs, err := ioutil.ReadFile(fmt.Sprintf("%s/proc/%d/cmdline", prefix, ppid))
	if err != nil {
		log.Warningf("Error reading cmdline for parent pid %d: %v", ppid, err)
		return false
	}
	for i, b := range pbs {
		if b == 0 {
			pbs[i] = byte(' ')
		}
	}


		
	finfo, err := os.Stat(fmt.Sprintf("%s/proc/%d", prefix, pi.Pid))
	if err != nil {
		log.Warningf("Could not stat /proc/%d: %v", pi.Pid, err)
		return false
	}
	sys := finfo.Sys().(*syscall.Stat_t)
	pi.UID = int(sys.Uid)
	pi.GID = int(sys.Gid)
	pi.ParentPid = ppid
	pi.ParentCmdLine = string(pbs)
	pi.ParentExePath = string(pexePath)
	pi.ExePath = exePath
	pi.Realm = realm
	pi.Sandbox = realm
	pi.LeaderPid = leaderpid
	pi.CmdLine = string(bcs)
	pi.loaded = true
	return true
}
