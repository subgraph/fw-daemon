package sgfw

import (
	"fmt"
	"net"
	"os"
	"bufio"
	"strings"
	"strconv"
	"encoding/binary"
)

const ReceiverSocketPath = "/tmp/fwoz.sock"


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

		if data[len(data)-1] == '\n' {
			data = data[0:len(data)-1]
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
				ip := make([]byte, 4)
		                binary.BigEndian.PutUint32(ip, rl[r].addr)
				hostname := ""

				if rl[r].hostname != "" {
					hostname = " (" + rl[r].hostname + ") "
				}

				portstr := strconv.Itoa(int(rl[r].port))

				if rl[r].port == 0 {
					portstr = "*"
				}

				ruledesc := fmt.Sprintf("id %v, %v | %v, src:%v -> %v%v: %v\n", rl[r].id, RuleModeString[rl[r].mode], RuleActionString[rl[r].rtype], rl[r].saddr, net.IP(ip), hostname, portstr)
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

			if len(tokens) != 5 {
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
				srcip = net.IP{0,0,0,0}
			}

			dstport := tokens[4]
			dstp, err := strconv.Atoi(dstport)

			if dstport != "*" && (err != nil || dstp < 0  || dstp > 65535) {
				log.Notice("IPC received invalid destination port: ", tokens[4])
				c.Write([]byte("Bad command: dst port was invalid"))
				return
			}

			if add {
				log.Noticef("Adding new rule to oz sandbox/fw: %v / %v -> %v : %v", w, srchost, dsthost, dstport)
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
