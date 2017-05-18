package sgfw

import (
	"net"
	"strings"
	"sync"
	"time"

//	"github.com/subgraph/go-nfnetlink"
	"github.com/google/gopacket/layers"
	nfqueue "github.com/subgraph/go-nfnetlink/nfqueue"
	"github.com/subgraph/go-procsnitch"
	"github.com/subgraph/fw-daemon/proc-coroner"
)

var monitoring = false
var mlock = sync.Mutex{}

type dnsEntry struct {
	name string
	ttl uint32
	exp time.Time
}

type dnsCache struct {
	ipMap map[int]map[string]dnsEntry
	lock  sync.Mutex
	done  chan struct{}
}

func newDNSEntry(hostname string, ttl uint32) dnsEntry {
	newEntry := dnsEntry{
		name: hostname,
		ttl:  ttl,
		exp:  time.Now().Add(time.Second * time.Duration(ttl)),
	}
	return newEntry
}

func newDNSCache() *dnsCache {
	newCache := &dnsCache{
		ipMap: make(map[int]map[string]dnsEntry),
		done:  make(chan struct{}),
	}
	newCache.ipMap[0] = make(map[string]dnsEntry)
	return newCache
}

func isNSTrusted(src net.IP) bool {
	return src.IsLoopback()
}

func (dc *dnsCache) processDNS(pkt *nfqueue.NFQPacket) {
	dns := &dnsMsg{}
	if !dns.Unpack(pkt.Packet.Layer(layers.LayerTypeDNS).LayerContents()) {
		log.Warning("Failed to Unpack DNS message")
		return
	}
	if !dns.response {
		return
	}
	if len(dns.question) != 1 {
		log.Warningf("Length of DNS Question section is not 1 as expected: %d", len(dns.question))
		return
	}
	q := dns.question[0]
	if q.Qtype == dnsTypeA {
		srcip, _ := getPacketIP4Addrs(pkt)
		pinfo := getEmptyPInfo()
		if !isNSTrusted(srcip) {
			pinfo, _  = findProcessForPacket(pkt, true, procsnitch.MATCH_LOOSEST)

			if pinfo == nil {
				log.Warningf("Skipping attempted DNS cache entry for process that can't be found: %v -> %v\n", q.Name, dns.answer)
				return
			}
		}
//log.Notice("XXX: PROCESS LOOKUP -> ", pinfo)
		dc.processRecordA(q.Name, dns.answer, pinfo.Pid)
		return
	}
	log.Infof("Unhandled DNS message: %v", dns)

}

/*func checker(c *dnsCache) {
	for {
		log.Error("CACHE CHECKER")
		c.lock.Lock()
		for k, v := range c.ipMap {
			log.Errorf("IN CACHE: %v -> %v\n", k, v)
		}
		c.lock.Unlock()
		time.Sleep(2 * time.Second)
	}
} */

func procDeathCallback(pid int, param interface{}) {
//	log.Warning("XXX: IN CALLBACK for pid: ", pid, " / param = ", param)

	if pid != 0 {
		cache := param.(*dnsCache)
		cache.lock.Lock()
		delete(cache.ipMap, pid)
		cache.lock.Unlock()
	}
}

func (dc *dnsCache) processRecordA(name string, answers []dnsRR, pid int) {
	dc.lock.Lock()
	defer dc.lock.Unlock()
	for _, rr := range answers {
		switch rec := rr.(type) {
		case *dnsRR_A:
			ip := net.IPv4(byte(rec.A>>24), byte(rec.A>>16), byte(rec.A>>8), byte(rec.A)).String()
			if strings.HasSuffix(name, ".") {
				name = name[:len(name)-1]
			}

			// Just in case.
			if pid < 0 {
				pid = 0
			}
			log.Noticef("______ Adding to dns map: %s: %s -> pid %d", name, ip, pid)

			_, ok := dc.ipMap[pid]
			if !ok {
				dc.ipMap[pid] = make(map[string]dnsEntry)
			}
			dc.ipMap[pid][ip] = newDNSEntry(name, rr.Header().TTL)

			if pid > 0 {
				log.Warning("Adding process to be monitored by DNS cache: ", pid)
				if !monitoring {
					mlock.Lock()
					if !monitoring {
						monitoring = true
//						go checker(dc)
						go pcoroner.MonitorThread(procDeathCallback, dc)
					}
					mlock.Unlock()
				}
				pcoroner.MonitorProcess(pid)
			}
			if !FirewallConfig.LogRedact {
				log.Infof("Adding %s: %s", name, ip)
			}
		case *dnsRR_CNAME:
			// Not that exotic; just ignore it
		default:
			log.Warningf("Unexpected RR type in answer section of A response: %v", rec)
		}
	}
}

func (dc *dnsCache) Lookup(ip net.IP, pid int) string {
	now := time.Now()
	dc.lock.Lock()
	defer dc.lock.Unlock()

	// empty procinfo can set this to -1
	if pid < 0 {
		pid = 0
	}

	if pid > 0 {
		entry, ok := dc.ipMap[pid][ip.String()]
		if ok {
			if now.Before(entry.exp) {
//				log.Noticef("XXX: LOOKUP on %v / %v = %v, ttl = %v / %v\n", pid, ip.String(), entry.name, entry.ttl, entry.exp)
				return entry.name
			} else {
				log.Warningf("Skipping expired per-pid (%d) DNS cache entry: %s -> %s / exp. %v (%ds)\n",
					pid, ip.String(), entry.name, entry.exp, entry.ttl)
			}
		}
	}

	str := ""
	entry, ok := dc.ipMap[0][ip.String()]
	if ok {
		if now.Before(entry.exp) {
			str = entry.name
//			log.Noticef("XXX: LOOKUP on %v / 0 RETURNING %v, ttl = %v / %v\n", ip.String(), str, entry.ttl, entry.exp)
		} else {
			log.Warningf("Skipping expired global DNS cache entry: %s -> %s / exp. %v (%ds)\n",
				ip.String(), entry.name, entry.exp, entry.ttl)
		}
	}

//log.Noticef("XXX: LOOKUP on %v / 0 RETURNING %v\n", ip.String(), str)
	return str
}
