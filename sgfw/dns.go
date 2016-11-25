package sgfw

import (
	"net"
	"strings"
	"sync"

	"github.com/subgraph/fw-daemon/nfqueue"
)

type dnsCache struct {
	ipMap map[string]string
	lock  sync.Mutex
	done  chan struct{}
}

func NewDnsCache() *dnsCache {
	return &dnsCache{
		ipMap: make(map[string]string),
		done:  make(chan struct{}),
	}
}

func (dc *dnsCache) processDNS(pkt *nfqueue.Packet) {
	dns := &dnsMsg{}
	if !dns.Unpack(pkt.Payload) {
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
		dc.processRecordA(q.Name, dns.answer)
		return
	}
	log.Infof("Unhandled DNS message: %v", dns)

}

func (dc *dnsCache) processRecordA(name string, answers []dnsRR) {
	dc.lock.Lock()
	defer dc.lock.Unlock()
	for _, rr := range answers {
		switch rec := rr.(type) {
		case *dnsRR_A:
			ip := net.IPv4(byte(rec.A>>24), byte(rec.A>>16), byte(rec.A>>8), byte(rec.A)).String()
			if strings.HasSuffix(name, ".") {
				name = name[:len(name)-1]
			}
			dc.ipMap[ip] = name
			if !FirewallConfig.LogRedact {
				log.Infof("Adding %s: %s", name, ip)
			}
		default:
			log.Warningf("Unexpected RR type in answer section of A response: %v", rec)
		}
	}
}

func (dc *dnsCache) Lookup(ip net.IP) string {
	dc.lock.Lock()
	defer dc.lock.Unlock()
	return dc.ipMap[ip.String()]
}
