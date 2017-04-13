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

func ReceiverLoop(c net.Conn) {
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

			srcip := net.ParseIP(tokens[2])

			if srcip == nil {
				log.Notice("IPC received invalid source host: ", tokens[2])
				c.Write([]byte("Bad command: source host address was invalid"))
				return
			}

			dstip := net.ParseIP(tokens[3])

			if dstip == nil {
				log.Notice("IPC received invalid destination host: ", tokens[3])
				c.Write([]byte("Bad command: dst host address was invalid"))
				return
			}

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

func OzReceiver() {
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

		go ReceiverLoop(fd)
        }

}
