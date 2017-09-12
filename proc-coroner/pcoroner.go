package pcoroner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type WatchProcess struct {
	Pid   int
	Inode uint64
	Ppid  int
	Stime int
}

type CallbackEntry struct {
	fn    procCB
	param interface{}
}

type procCB func(int, interface{})

var Callbacks []CallbackEntry

var pmutex = &sync.Mutex{}
var pidMap map[int]WatchProcess = make(map[int]WatchProcess)

func MonitorProcess(pid int) bool {
	pmutex.Lock()
	defer pmutex.Unlock()

	_, ok := pidMap[pid]

	if ok {
		return false
	}

	watcher := WatchProcess{Pid: pid}
	watcher.Inode = 0
	res := checkProcess(&watcher, true)

	if res {
		pidMap[pid] = watcher
	}

	return res
}

func UnmonitorProcess(pid int) {
	pmutex.Lock()
	defer pmutex.Unlock()
	delete(pidMap, pid)
	return
}

func AddCallback(cbfunc procCB, param interface{}) {
	cbe := CallbackEntry{cbfunc, param}
	Callbacks = append(Callbacks, cbe)
}

func MonitorThread(cbfunc procCB, param interface{}) {
	for {
		/*		if len(pidMap) == 0 {
				fmt.Println("TICK")
			} else { fmt.Println("len = ", len(pidMap)) } */
		pmutex.Lock()
		pmutex.Unlock()

		for pkey, pval := range pidMap {
			//			fmt.Printf("PID %v -> %v\n", pkey, pval)
			res := checkProcess(&pval, false)

			if !res {
				delete(pidMap, pkey)

				if cbfunc != nil {
					cbfunc(pkey, param)
				}
				for i := 0; i < len(Callbacks); i++ {
					Callbacks[i].fn(pkey, Callbacks[i].param)
				}
				continue
			}

		}

		time.Sleep(1 * time.Second)
	}
}

func checkProcess(proc *WatchProcess, init bool) bool {
	ppath := fmt.Sprintf("/proc/%d/stat", proc.Pid)
	f, err := os.Open(ppath)
	if err != nil {
		//		fmt.Printf("Error opening path %s: %s\n", ppath, err)
		return false
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		fmt.Printf("Error calling stat on file %s: %s\n", ppath, err)
		return false
	}
	sb, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		fmt.Println("Unexpected error reading stat information from proc file")
	} else if init {
		proc.Inode = sb.Ino
	} else {
		if sb.Ino != proc.Inode {
			fmt.Printf("/proc inode mismatch for process %d: %v vs %v\n", proc.Pid, sb.Ino, proc.Inode)
			return false
		}
	}

	var buf [512]byte
	nread, err := f.Read(buf[:])
	if err != nil {
		fmt.Printf("Error reading stat for process %d: %v", proc.Pid, err)
		return true
	} else if nread <= 0 {
		fmt.Printf("Unexpected error reading stat for process %d", proc.Pid)
		return true
	}

	bstr := string(buf[:])
	//	fmt.Println("sstr = ", bstr)

	fields := strings.Split(bstr, " ")

	if len(fields) < 22 {
		fmt.Printf("Unexpected error reading data from /proc stat for process %d", proc.Pid)
		return true
	}

	ppid, err := strconv.Atoi(fields[3])
	if err != nil {
		ppid = -1
	}

	if init {
		proc.Ppid = ppid
	} else if proc.Ppid != ppid {
		fmt.Printf("Cached process ppid did not match value in /proc: %v vs %v\n", proc.Ppid, ppid)
		return false
	}

	stime, err := strconv.Atoi(fields[21])
	if err != nil {
		stime = -1
	}

	if init {
		proc.Stime = stime
	} else if proc.Stime != stime {
		fmt.Printf("Cached process start time did not match value in /proc: %v vs %v\n", proc.Stime, stime)
		return false
	}

	return true
}
