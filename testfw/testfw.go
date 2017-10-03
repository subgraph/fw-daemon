package main

import (
	"fmt"
	"log"
	"time"
)

var dbuso *dbusObjectP


func main() {
	fmt.Println("Starting up test units...")

	_, err := newDbusServer()
	if err != nil {
		log.Fatal("Error:", err)
		return
	}

	dbuso, err := newDbusObjectAdd()
	if err != nil {
		log.Fatal("Failed to connect to dbus system bus: %v", err)
	}

	res := CallAddTestVPC(dbuso, "udp", "10.0.0.1", 61921, "8.8.8.8", 53, "dnsthing.google.com")
	fmt.Println("res =", res)


	fmt.Println("Waiting until interrupted...")

	for true {
		time.Sleep(1 * time.Second)
	}

}
