package sgfw

import (
	"fmt"
	"net"
	"os"
	"bufio"
	"strings"
	"strconv"
)

const ReceiverSocketPath = "/tmp/fwoz.sock"


func canAddRule(rule sandboxRule) bool {

	for i := 0; i < len(sandboxRules); i++ {

		if rule.SrcIf.Equal(sandboxRules[i].SrcIf) && rule.Whitelist != sandboxRules[i].Whitelist {
			return false
		}

	}

	return true
}

func ruleExists(rule sandboxRule) int {

	for i := 0; i < len(sandboxRules); i++ {

		if rule.Whitelist == sandboxRules[i].Whitelist && rule.SrcIf.Equal(sandboxRules[i].SrcIf) && rule.DstIP.Equal(sandboxRules[i].DstIP) && rule.DstPort == sandboxRules[i].DstPort {
			return i
		}

	}

	return -1
}

func addFWRule(fw *Firewall, whitelist bool, srchost, dsthost string, dstport uint16) error {
	policy := fw.PolicyForPath("*")
	rulestr := ""

	if whitelist {
		rulestr += "ALLOW"
	} else {
		rulestr += "DENY"
	}

	rulestr += "|" + dsthost + ":" + strconv.Itoa(int(dstport)) + "|SESSION|" + srchost
	_, err := policy.parseRule(rulestr, true)

	return err
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
			banner := fmt.Sprintf("There are a total of %d rule(s).\n", len(sandboxRules))
			c.Write([]byte(banner))

			for i := 0; i < len(sandboxRules); i++ {
				rulestr := ""

				if sandboxRules[i].Whitelist {
					rulestr += "whitelist"
				} else {
					rulestr += "blacklist"
				}

				rulestr += " " + sandboxRules[i].SrcIf.String() + " -> " + sandboxRules[i].DstIP.String() + " : " + strconv.Itoa(int(sandboxRules[i].DstPort)) + "\n"
				c.Write([]byte(rulestr))
			}

			return
		} else {
			tokens := strings.Split(data, " ")

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

			dstip := net.IP{0,0,0,0}

			dstport, err := strconv.Atoi(tokens[4])

			if err != nil || dstport <= 0  || dstport > 65535 {
				log.Notice("IPC received invalid destination port: ", tokens[4])
				c.Write([]byte("Bad command: dst port was invalid"))
				return
			}

			rule := sandboxRule { srcip, dstip, uint16(dstport), w }

			if add && !canAddRule(rule) {
				log.Notice("Could not add rule of mismatching type: ", rule)
				c.Write([]byte("Error: cannot add rule that would result in mixed whitelist and blacklist"))
				return
			}

			exists := ruleExists(rule)

			if add && exists != -1 {
				log.Notice("IP received request to add existing rule: ", rule)
				c.Write([]byte("Error: cannot add already existing rule"))
				return
			} else if !add && exists == -1 {
				log.Notice("IP received request to remove non-existent rule: ", rule)
				c.Write([]byte("Error: could not remove non-existent rule"))
				return
			}

			if add {
				log.Notice("Adding new rule to oz sandbox/fw: ", rule)
				sandboxRules = append(sandboxRules, rule)
				err := addFWRule(fw, w, srchost, dsthost, uint16(dstport))
				if err != nil {
					log.Error("Error adding dynamic OZ firewall rule to fw-daemon: ", err)
				} else {
					log.Notice("XXX: rule also successfully added to fw-daemon")
				}
			} else {
				log.Notice("Removing new rule from oz sandbox/fw: ", rule)
				sandboxRules = append(sandboxRules[:exists], sandboxRules[exists+1:]...)
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
