package sgfw

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/subgraph/oz/ipc"
)

const ReceiverSocketPath = "/var/run/fw-daemon/fwoz.sock"

type OzInitProc struct {
	Name      string
	Pid       int
	SandboxID int
}

var OzInitPids []OzInitProc = []OzInitProc{}

func addInitPid(pid int, name string, sboxid int) {
	fmt.Println("::::::::::: init pid added: ", pid, " -> ", name)
	for i := 0; i < len(OzInitPids); i++ {
		if OzInitPids[i].Pid == pid {
			return
		}
	}

	ozi := OzInitProc{Name: name, Pid: pid, SandboxID: sboxid}
	OzInitPids = append(OzInitPids, ozi)
}

func removeInitPid(pid int) {
	fmt.Println("::::::::::: removing PID: ", pid)
	for i := 0; i < len(OzInitPids); i++ {
		if OzInitPids[i].Pid == pid {
			OzInitPids = append(OzInitPids[:i], OzInitPids[i+1:]...)
			return
		}
	}
}

func addFWRule(fw *Firewall, whitelist bool, srchost, dsthost, dstport string) error {
	policy := fw.PolicyForPath("*")
	rulestr := ""

	if whitelist {
		rulestr += "ALLOW"
	} else {
		rulestr += "DENY"
	}

	rulestr += "|" + dsthost + ":" + dstport + "|SESSION|" + srchost
	_, err := policy.parseRule(rulestr, true)

	return err
}

func removeAllByIP(fw *Firewall, srcip string) bool {
	log.Notice("XXX: Attempting to remove all rules associated with Oz interface: ", srcip)
	saddr := net.ParseIP(srcip)

	if saddr == nil {
		return false
	}

	policy := fw.PolicyForPath("*")
	nrm := 0

	for _, rr := range policy.rules {
		if rr.saddr != nil && rr.saddr.Equal(saddr) {
			log.Notice("XXX: removing ephemeral rules by Oz interface ", srcip, ": ", rr)
			policy.removeRule(rr)
			nrm++
		}
	}

	if nrm == 0 {
		log.Notice("XXX: did not remove any rules for interface")
	}

	return true
}

func ReceiverLoop(fw *Firewall, c net.Conn) {
	defer c.Close()
	bio := bufio.NewReader(c)

	for {
		buf, err := bio.ReadBytes('\n')

		if err != nil {
			log.Notice("Error reading data from IPC client: ", err)
			return
		}

		data := string(buf)

		log.Notice("Received incoming IPC:", data)

		if data[len(data)-1] == '\n' {
			data = data[0 : len(data)-1]
		}

		if data == "dump" {
			log.Notice("Dumping oz-firewall rule set to client...")
			rl := fw.PolicyForPath("*").rules

			totalIRules := 0

			for r := 0; r < len(rl); r++ {
				if rl[r].saddr != nil {
					totalIRules++
				}
			}

			banner := fmt.Sprintf("There are a total of %d rule(s).\n", totalIRules)

			c.Write([]byte(banner))

			for r := 0; r < len(rl); r++ {
				hostname := ""

				if rl[r].hostname != "" {
					hostname = " (" + rl[r].hostname + ") "
				}

				portstr := strconv.Itoa(int(rl[r].port))

				if rl[r].port == 0 {
					portstr = "*"
				}

				ruledesc := fmt.Sprintf("id %v, %v | %v, src:%v -> %v%v: %v\n", rl[r].id, RuleModeString[rl[r].mode], RuleActionString[rl[r].rtype], rl[r].saddr, rl[r].addr, hostname, portstr)
				c.Write([]byte(ruledesc))
			}

			/*			for i := 0; i < len(sandboxRules); i++ {
						rulestr := ""

						if sandboxRules[i].Whitelist {
							rulestr += "whitelist"
						} else {
							rulestr += "blacklist"
						}

						rulestr += " " + sandboxRules[i].SrcIf.String() + " -> " + sandboxRules[i].DstIP.String() + " : " + strconv.Itoa(int(sandboxRules[i].DstPort)) + "\n"
						c.Write([]byte(rulestr))
					} */

			return
		} else {
			tokens := strings.Split(data, " ")

			if len(tokens) == 2 && tokens[0] == "removeall" {
				log.Notice("Attempting to remove all: ", tokens[1])
				removeAllByIP(fw, tokens[1])
				return
			}

			if tokens[0] == "register-init" && len(tokens) >= 3 {
				initp := tokens[1]

				initpid, err := strconv.Atoi(initp)

				if err != nil {
					log.Notice("IPC received invalid oz-init pid: ", initp)
					c.Write([]byte("Bad command: init pid was invalid"))
					return
				}

				sboxid, err := strconv.Atoi(tokens[3])
				if err != nil {
					log.Notice("IPC received invalid oz sbox number: ", tokens[3])
					log.Notice("Data: %v", data)
					c.Write([]byte("Bad command: sandbox id was invalid"))
					return
				}

				// ozname := strings.Join(tokens[2:], " ")
				log.Notice("IPC message for register-init OK.")
				addInitPid(initpid, tokens[2], sboxid)
				c.Write([]byte("OK"))
				return
			} else if tokens[0] == "unregister-init" && len(tokens) == 2 {
				initp := tokens[1]
				initpid, err := strconv.Atoi(initp)

				if err != nil {
					log.Notice("IPC received invalid oz-init pid: ", initp)
					c.Write([]byte("Bad command: init pid was invalid"))
					return
				}

				removeInitPid(initpid)
				c.Write([]byte("OK.\n"))
			}

			if len(tokens) != 6 {
				log.Notice("IPC received invalid command: " + data)
				c.Write([]byte("Received bad number of parameters.\n"))
				return
			} else if tokens[0] != "add" && tokens[0] != "remove" {
				log.Notice("IPC received invalid command: " + data)
				c.Write([]byte("Unrecognized command.\n"))
				return
			} else if tokens[1] != "whitelist" && tokens[1] != "blacklist" {
				log.Notice("IPC received invalid command: " + data)
				c.Write([]byte("Bad command: must specify either whitelist or blacklist.\n"))
				return
			}

			add := true

			if tokens[0] == "remove" {
				add = false
			}

			w := true

			if tokens[1] == "blacklist" {
				w = false
			}

			srchost := tokens[2]
			dsthost := tokens[3]
			srcip := net.ParseIP(srchost)

			if srcip == nil {
				log.Notice("IP conversion failed: ", srchost)
				srcip = net.IP{0, 0, 0, 0}
			}

			dstport := tokens[4]
			dstp, err := strconv.Atoi(dstport)

			if dstport != "*" && (err != nil || dstp < 0 || dstp > 65535) {
				log.Notice("IPC received invalid destination port: ", tokens[4])
				c.Write([]byte("Bad command: dst port was invalid"))
				return
			}

			/*			initp := tokens[5]
						initpid, err := strconv.Atoi(initp)

						if err != nil {
							log.Notice("IPC received invalid oz-init pid: ", initp)
							c.Write([]byte("Bad command: init pid was invalid"))
							return
						} */

			if add {
				log.Noticef("Adding new rule to oz sandbox/fw: %v / %v -> %v : %v", w, srchost, dsthost, dstport)
				//				addInitPid(initpid)
				err := addFWRule(fw, w, srchost, dsthost, dstport)
				if err != nil {
					log.Error("Error adding dynamic OZ firewall rule to fw-daemon: ", err)
				} else {
					log.Notice("XXX: rule also successfully added to fw-daemon")
				}
			} else {
				log.Notice("Removing new rule from oz sandbox/fw... ")
			}

			log.Notice("IPC received command: " + data)
			c.Write([]byte("OK.\n"))
			return
		}

	}

}

func OzReceiver(fw *Firewall) {
	log.Notice("XXX: dispatching oz receiver...")

	sboxes, err := getSandboxes()

	if err != nil {
		log.Warning("Error retrieving list of running Oz sandbox init processes: ", err)
	} else {

		if len(sboxes) > 0 {
			log.Warning("Adding existing Oz sandbox init pids...")
			for s := 0; s < len(sboxes); s++ {
				//profname := fmt.Sprintf("%s (%d)", sboxes[s].Profile, sboxes[s].Id)
				addInitPid(sboxes[s].InitPid, sboxes[s].Profile, sboxes[s].Id)
			}
		} else {
			log.Warning("It does not appear there were any Oz sandboxed processes already launched.")
		}

	}

	os.Remove(ReceiverSocketPath)
	lfd, err := net.Listen("unix", ReceiverSocketPath)
	if err != nil {
		log.Fatal("Could not open oz receiver socket:", err)
	}

	for {
		fd, err := lfd.Accept()
		if err != nil {
			log.Fatal("Could not accept receiver client:", err)
		}

		go ReceiverLoop(fw, fd)
	}

}

type ListProxiesMsg struct {
	_ string "ListProxies"
}

type ListProxiesResp struct {
	Proxies []string "ListProxiesResp"
}

func ListProxies() ([]string, error) {
	resp, err := clientSend(&ListProxiesMsg{})
	if err != nil {
		return nil, err
	}
	body, ok := resp.Body.(*ListProxiesResp)
	if !ok {
		return nil, errors.New("ListProxies response was not expected type")
	}
	return body.Proxies, nil
}

const OzSocketName = "@oz-control"

var bSockName = OzSocketName

var messageFactory = ipc.NewMsgFactory(
	new(ListProxiesMsg),
	new(ListProxiesResp),
)

func clientConnect() (*ipc.MsgConn, error) {
	bSockName = os.Getenv("SOCKET_NAME")

	if bSockName != "" {
		fmt.Println("Attempting to connect on custom socket provided through environment: ", bSockName)

		if bSockName[0:1] != "@" {
			fmt.Println("Environment variable specified invalid socket name... prepending @")
			bSockName = "@" + bSockName
		}

	} else {
		bSockName = OzSocketName
	}

	return ipc.Connect(bSockName, messageFactory, nil)
}

func clientSend(msg interface{}) (*ipc.Message, error) {
	c, err := clientConnect()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	rr, err := c.ExchangeMsg(msg)
	if err != nil {
		return nil, err
	}

	resp := <-rr.Chan()
	rr.Done()
	return resp, nil
}
