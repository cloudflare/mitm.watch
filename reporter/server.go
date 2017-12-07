package main

import (
	"errors"
	"log"
	"net"
	"strings"
	"time"
)

const (
	originAddress  = ""
	sessionTimeout = 60 * time.Second

	// Host name (suffix) for various purposes.
	hostReporter   = "l.ls-l.info"   // Reporter API
	hostSuffixIPv4 = ".l4.ls-l.info" // IPv4 tests
	hostSuffixIPv6 = ".l6.ls-l.info" // IPv6 tests
)

// handleConnection processes a new connection. If is able to parse a single TLS
// record containing a TLS Client Hello with a SNI, it will try to route that.
// Otherwise it will fallback to proxying to the origin.
func handleConnection(c net.Conn) {
	defer c.Close()
	startTime := time.Now()
	c.SetDeadline(startTime.Add(sessionTimeout))

	remoteAddr := c.RemoteAddr().String()
	wrappedConn := wrapConn(c)
	buffer, err := wrappedConn.peek(4096)
	if len(buffer) == 0 {
		log.Printf("%s - failed to read a record: %v\n", remoteAddr, err)
		return
	}
	sni := parseClientHello(buffer)
	log.Printf("%s - SNI: %v\n", remoteAddr, sni)

	switch {
	case sni == hostReporter:
		err = errors.New("not implemented yet")
	case strings.HasSuffix(sni, hostSuffixIPv4) || strings.HasSuffix(sni, hostSuffixIPv6):
		err = errors.New("not implemented yet")
	case originAddress == "":
		err = errors.New("no upstream configured")
	default:
		err = proxyConnection(wrappedConn, originAddress)
	}
	if err != nil {
		log.Printf("%s - error handling connection: %v\n", remoteAddr, err)
	}
}

func main() {
	address := ":4433"
	l, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept failed - %v", err)
			continue
		}
		go handleConnection(c)
	}
}
