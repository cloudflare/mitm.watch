package main

import (
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Maximum number of new connections that can be queued for processing.
// In the current implementation this will result in a growing number of
// blocking goroutines when the queue is full. Should probably be changed.
const maxHttpsQueueSize = 1024

// RequestClaimer is given a hostname and should return whether the listener
// should claim the request and if so, whether it should record the data.
type RequestClaimer func(host string) (claimed bool, record bool)

type listener struct {
	net.Listener

	initialReadTimeout time.Duration
	originAddress      string

	ClaimRequest RequestClaimer

	// queue for new connections, intended for reporter or test services.
	newc chan net.Conn
	// used to synchronize closing newc.
	connectionsWg sync.WaitGroup
}

func newListener(ln net.Listener, initialReadTimeout time.Duration, originAddress string, claimer RequestClaimer) *listener {
	newc := make(chan net.Conn, maxHttpsQueueSize)
	return &listener{
		Listener:           ln,
		initialReadTimeout: initialReadTimeout,
		originAddress:      originAddress,
		ClaimRequest:       claimer,
		newc:               newc,
	}
}

// a TLS record containing a fatal alert for unrecognized_name.
var tlsRecordUnrecognizedName = []byte{21, 3, 1, 0, 2, 2, 112}

// handleConnection processes a new connection. It will proxy the connection or
// forward it to the HTTPS listener.
//
// The decision to handle the connection or not is driven by parsing a TLS
// Client Hello, if that is not possible it will assume that it needs to be
// proxied.
func (ln *listener) handleConnection(c net.Conn) {
	servedByUs := false
	defer func() {
		if !servedByUs {
			// proxied or error, prevent fd leak.
			c.Close()
			ln.connectionsWg.Done()
		}
	}()
	startTime := time.Now()
	c.SetReadDeadline(startTime.Add(ln.initialReadTimeout))

	remoteAddr := c.RemoteAddr().String()
	wrappedConn := wrapConn(c)
	buffer, err := wrappedConn.peek(4096)
	if len(buffer) == 0 {
		log.Printf("%s - failed to read a record: %v\n", remoteAddr, err)
		return
	}
	sni := parseClientHello(buffer)
	log.Printf("%s - SNI: %v\n", remoteAddr, sni)

	// Disable timeout again, this is the responsibility of the (upstream)
	// server configuration.
	c.SetReadDeadline(time.Time{})

	servedByUs, _ = ln.ClaimRequest(sni)
	// TODO handle TCP logging
	switch {
	case servedByUs:
		ln.newc <- wrappedConn
		ln.connectionsWg.Done()
	case ln.originAddress == "":
		log.Printf("%s - no upstream configured", remoteAddr)
		c.Write(tlsRecordUnrecognizedName)
	default:
		if err := proxyConnection(wrappedConn, ln.originAddress); err != nil {
			log.Printf("%s - error proxying connection: %v\n", remoteAddr, err)
		}
	}
}

func (ln *listener) Serve() error {
	defer func() {
		ln.connectionsWg.Wait()
		close(ln.newc)
	}()
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		c, err := ln.Listener.Accept()
		if err != nil {
			// in case too many file descriptors are open, delay
			// accept (based on net/http/server.go)
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("listener: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		ln.connectionsWg.Add(1)
		go ln.handleConnection(c)
	}
}

func (ln *listener) Accept() (net.Conn, error) {
	c, ok := <-ln.newc
	if !ok {
		return nil, http.ErrServerClosed
	}

	// let dead connections eventually go away (mimic
	// http.ListenAndServe behavior).
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(3 * time.Minute)
	}

	return c, nil
}
