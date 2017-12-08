package main

import (
	"log"
	"net"
	"net/http"
	"time"
)

const (
	// configuration used in listener.go
	originAddress  = ""
	sessionTimeout = 60 * time.Second

	// Host name (suffix) for various purposes.
	hostReporter   = "l.ls-l.info"   // Reporter API
	hostSuffixIPv4 = ".l4.ls-l.info" // IPv4 tests
	hostSuffixIPv6 = ".l6.ls-l.info" // IPv6 tests
)

func main() {
	address := ":4433"
	l, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	wl := newListener(l)
	err = http.ServeTLS(wl, nil, "server.pem", "server.pem")
	if err != nil {
		log.Printf("ServeTLS failed: %v\n", err)
	}
}
