package main

import (
	"log"
	"net"
	"time"
)

// RequestClaimer is given a hostname and should return whether the listener
// should claim the request and if so, whether it should record the data.
type RequestClaimer func(host string) (claimed bool, record bool)

type listener struct {
	net.Listener

	initialReadTimeout time.Duration
	originAddress      string

	ClaimRequest RequestClaimer
}

func newListener(ln net.Listener, initialReadTimeout time.Duration, originAddress string, claimer RequestClaimer) *listener {
	return &listener{ln, initialReadTimeout, originAddress, claimer}
}

// a TLS record containing a fatal alert for unrecognized_name.
var tlsRecordUnrecognizedName = []byte{21, 3, 1, 0, 2, 2, 112}

// handleConnection processes a new connection. If it claims the connection
// (e.g. if it decides to proxy the connection), then it will return true.
// Otherwise (if the request must be handled by ourselves), it returns the
// modified connection and false.
//
// The decision to handle the connection or not is driven by parsing a TLS
// Client Hello, if that is not possible it will assume that it needs to be
// proxied.
func (ln *listener) handleConnection(c net.Conn) (net.Conn, bool) {
	startTime := time.Now()
	c.SetReadDeadline(startTime.Add(ln.initialReadTimeout))

	remoteAddr := c.RemoteAddr().String()
	wrappedConn := wrapConn(c)
	// TODO this blocks the Accept thread...
	buffer, err := wrappedConn.peek(4096)
	if len(buffer) == 0 {
		log.Printf("%s - failed to read a record: %v\n", remoteAddr, err)
		return nil, true
	}
	sni := parseClientHello(buffer)
	log.Printf("%s - SNI: %v\n", remoteAddr, sni)

	// Disable timeout again, this is the responsibility of the (upstream)
	// server configuration.
	c.SetReadDeadline(time.Time{})

	claimed, _ := ln.ClaimRequest(sni)
	// TODO handle TCP logging
	switch {
	case claimed:
		return wrappedConn, false
	case ln.originAddress == "":
		log.Printf("%s - no upstream configured", remoteAddr)
		go func() {
			c.Write(tlsRecordUnrecognizedName)
			c.Close()
		}()
		return nil, true
	default:
		go func() {
			defer c.Close()
			if err := proxyConnection(wrappedConn, ln.originAddress); err != nil {
				log.Printf("%s - error proxying connection: %v\n", remoteAddr, err)
			}
		}()
		return nil, true
	}
}

func (ln *listener) Accept() (net.Conn, error) {
	for {
		c, err := ln.Listener.Accept()

		// let dead connections eventually go away (mimic
		// http.ListenAndServe behavior).
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(3 * time.Minute)
		}

		c, handled := ln.handleConnection(c)
		if handled {
			continue
		}
		return c, err
	}
}
