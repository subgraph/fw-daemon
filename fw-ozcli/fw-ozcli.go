package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

const ReceiverSocketPath = "/var/run/fw-daemon/fwoz.sock"

func reader(r io.Reader) {
	buf := make([]byte, 1024)

	for {
		n, err := r.Read(buf[:])
		if err != nil {
			return
		}
		fmt.Println(string(buf[0:n]))
	}
}

func main() {
	dump := flag.Bool("d", false, "dump current oz-fw rules")
	whitelist := flag.Bool("w", false, "submit whitelist rule")
	blacklist := flag.Bool("b", false, "submit blacklist rule")
	src := flag.String("src", "", "source IP address")
	dst := flag.String("dst", "", "destination IP address")
	port := flag.Int("port", 0, "destination port number")
	rm := flag.Bool("rm", false, "remove entry from rules (default is add)")

	flag.Parse()

	if !*dump {

		if *src == "" {
			log.Fatal("Error: must specify source address with -src")
		} else if *dst == "" {
			log.Fatal("Error: must specify destination address with -dst")
		} else if *port == 0 {
			log.Fatal("Error: must specify destination port with -port")
		} else if *port <= 0 || *port > 65535 {
			log.Fatal("Error: invalid port was specified")
		} else if !*whitelist && !*blacklist {
			log.Fatal("Error: -w or -b must be specified to whitelist or blacklist entry")
		} else if *whitelist && *blacklist {
			log.Fatal("Error: -w and -b cannot be specified together")
		}

	} else {
		fmt.Println("Attempting to dump active rule list.")
	}

	c, err := net.Dial("unix", ReceiverSocketPath)
	if err != nil {
		log.Fatal("Could not establish connection to listener:", err)
	}

	defer c.Close()

	if *dump {
		c.Write([]byte("dump\n"))
		reader(c)
		fmt.Println("Done.")
	} else {
		reqstr := ""

		if *rm {
			reqstr += "remove "
		} else {
			reqstr += "add "
		}

		if *whitelist {
			reqstr += "whitelist"
		} else {
			reqstr += "blacklist"
		}

		reqstr += " " + *src + " " + *dst + " " + strconv.Itoa(*port) + "\n"
		c.Write([]byte(reqstr))
		reader(c)
		fmt.Println("Done.")
	}

}
