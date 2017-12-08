package main

import (
	"log"
	"net"
	"strings"
	"time"
)

type listener struct {
	net.Listener
}

func newListener(ln net.Listener) *listener {
	return &listener{ln}
}

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
	c.SetDeadline(startTime.Add(sessionTimeout))

	remoteAddr := c.RemoteAddr().String()
	wrappedConn := wrapConn(c)
	buffer, err := wrappedConn.peek(4096)
	if len(buffer) == 0 {
		log.Printf("%s - failed to read a record: %v\n", remoteAddr, err)
		return nil, true
	}
	sni := parseClientHello(buffer)
	log.Printf("%s - SNI: %v\n", remoteAddr, sni)

	switch {
	case sni == hostReporter:
		// pass to HTTP handler, handle API requests.
		return wrappedConn, false
	case strings.HasSuffix(sni, hostSuffixIPv4) || strings.HasSuffix(sni, hostSuffixIPv6):
		// pass to HTTP handler, handling a basic response.
		// TODO configure logging here.
		return wrappedConn, false
	case originAddress == "":
		log.Printf("%s - no upstream configured", remoteAddr)
		c.Close()
		return nil, true
	default:
		go func() {
			defer c.Close()
			if err := proxyConnection(wrappedConn, originAddress); err != nil {
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
