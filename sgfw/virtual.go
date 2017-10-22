package sgfw

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/godbus/dbus"
	"github.com/subgraph/go-procsnitch"
)

type virtualPkt struct {
	pol       *Policy
	name      string
	pinfo     *procsnitch.Info
	optstring string
	prompting bool
	prompter  *prompter
	guid      string
	timestamp time.Time
	is_socks  bool
	_proto    string
	srcip     net.IP
	sport     uint16
	dstip     net.IP
	dport     uint16
}

var tdb *dbusObjectP
var tdbMutex = &sync.Mutex{}
var tdbInit = false

func init() {
	fmt.Println("Initializing virtual packet test subsystem...")

	conn, err := dbus.SystemBus()
	if err != nil {
		fmt.Println("Error setting up server on test DBus path:", err)
		tdb = &dbusObjectP{nil}
	}

	tdb = &dbusObjectP{conn.Object("com.subgraph.FirewallTest", "/com/subgraph/FirewallTest")}
	tdbInit = true
}

func sendSGFWTestAlert(accepted int, guid string, other string) bool {
	var dres bool

	if !tdbInit {
		fmt.Println("Skipping over invocation of SGFWTestAlert(); DBus method was not properly bound")
		return false
	}

	tdbMutex.Lock()
	defer tdbMutex.Unlock()

	call := tdb.Call("com.subgraph.FirewallTest.SGFWTestAlert", 0, int32(accepted), guid, other)
	err := call.Store(&dres)
	if err != nil {
		fmt.Println("Error sending DBus SGFWTestAlert() notification:", err)
		return false
	}

	return true
}

func (vp *virtualPkt) sandbox() string {
	return vp.pinfo.Sandbox
}

func (vp *virtualPkt) getTimestamp() string {
	return vp.timestamp.Format("15:04:05.00")
}

func (vp *virtualPkt) socks() bool {
	return vp.is_socks
}

func (vp *virtualPkt) policy() *Policy {
	return vp.pol
}

func (vp *virtualPkt) procInfo() *procsnitch.Info {
	if vp.pinfo == nil {
		return getEmptyPInfo()
	}

	return vp.pinfo
}

func (vp *virtualPkt) getOptString() string {
	return vp.optstring
}

func (vp *virtualPkt) hostname() string {
	return vp.name
}

func (vp *virtualPkt) src() net.IP {
	return vp.srcip
}

func (vp *virtualPkt) dst() net.IP {
	return vp.dstip
}

func (vp *virtualPkt) proto() string {
	return vp._proto
}

func (vp *virtualPkt) srcPort() uint16 {
	return vp.sport
}

func (vp *virtualPkt) dstPort() uint16 {
	return vp.dport
}

func (vp *virtualPkt) accept() {
	fmt.Println("VIRTUAL PACKET ACCEPTED")
	sendSGFWTestAlert(1, vp.getGUID(), "")
}

func (vp *virtualPkt) acceptTLSOnly() {
	fmt.Println("VIRTUAL PACKET ACCEPTED (TLSONLY)")
	sendSGFWTestAlert(1, vp.getGUID(), "tls")
}

func (vp *virtualPkt) drop() {
	fmt.Println("VIRTUAL PACKET DROPPED")
	sendSGFWTestAlert(0, vp.getGUID(), "")
}

func (vp *virtualPkt) setPrompter(val *prompter) {
	vp.prompter = val
}

func (vp *virtualPkt) getPrompter() *prompter {
	return vp.prompter
}

func (vp *virtualPkt) getGUID() string {
	if vp.guid == "" {
		vp.guid = genGUID()
	}

	return vp.guid
}

func (vp *virtualPkt) getPrompting() bool {
	return vp.prompting
}

func (vp *virtualPkt) setPrompting(val bool) {
	vp.prompting = val
}

func (vp *virtualPkt) print() string {
	desc := fmt.Sprintf("virtualPkt { src %s:%u, dst %s:%u (%s) proto %s",
		vp.srcip, vp.sport, vp.dstip, vp.dport, vp.hostname, vp._proto)

	// pinfo excluded
	desc += fmt.Sprintf(" socks=%v   [policy=%s]", vp.is_socks, vp.pol.application)
	desc += fmt.Sprintf("  prompting=%v ts=%s", vp.prompting, vp.getTimestamp())
	desc += fmt.Sprintf(" guid=%s   [optstring=%s] }", vp.getGUID(), vp.optstring)
	return desc
}

func (vp *virtualPkt) SetPacket(proto string, srcip net.IP, sport uint16, dstip net.IP, dport uint16, hostname string) bool {
	vp._proto = proto
	vp.srcip = srcip
	vp.dstip = dstip
	vp.sport = sport
	vp.dport = dport
	vp.name = hostname
	return true
}
