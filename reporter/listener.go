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
// should claim the request and if a ServerCapture template if it should record.
type RequestClaimer func(host string) (claimed bool, subtestID int)

// ServerCaptureNotifier is emitted when a server capture is completed.
type ServerCaptureNotifier func(name string, capture *ServerCapture)

type listener struct {
	net.Listener

	initialReadTimeout time.Duration
	originAddress      string
	flashpolicyserver  *FlashPolicyServer

	ClaimRequest RequestClaimer

	// invoked when a server capture is ready.
	ServerCaptureReady ServerCaptureNotifier

	// queue for new connections, intended for reporter or test services.
	newc chan net.Conn
	// used to synchronize closing newc.
	connectionsWg sync.WaitGroup
}

func newListener(ln net.Listener, initialReadTimeout time.Duration, originAddress string, claimer RequestClaimer, serverCaptureReady ServerCaptureNotifier, flashpolicyserver *FlashPolicyServer) *listener {
	newc := make(chan net.Conn, maxHttpsQueueSize)
	return &listener{
		Listener:           ln,
		initialReadTimeout: initialReadTimeout,
		originAddress:      originAddress,
		flashpolicyserver:  flashpolicyserver,
		ClaimRequest:       claimer,
		ServerCaptureReady: serverCaptureReady,
		newc:               newc,
	}
}

// a TLS record containing a fatal alert for unrecognized_name.
var tlsRecordUnrecognizedName = []byte{21, 3, 1, 0, 2, 2, 112}

// a TLS record containing a fatal alert for handshake_failure.
var tlsRecordHandshakeFailure = []byte{21, 3, 1, 0, 2, 2, 40}

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

	// let dead connections eventually go away (mimic
	// http.ListenAndServe behavior).
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(3 * time.Minute)
	}

	remoteAddr := c.RemoteAddr().String()
	localAddr := c.LocalAddr().String()
	peekableConn := NewPeekableConn(c)
	buffer, err := peekableConn.peek(4096)
	if len(buffer) == 0 {
		log.Printf("%s / %s - failed to read a record: %v\n", remoteAddr, localAddr, err)
		return
	}
	sni, isTLS := parseClientHello(buffer)
	log.Printf("%s / %s - SNI: %v (isTLS: %t)\n", remoteAddr, localAddr, sni, isTLS)

	// Disable timeout again, this is the responsibility of the (upstream)
	// server configuration.
	c.SetReadDeadline(time.Time{})

	servedByUs, subtestID := ln.ClaimRequest(sni)
	switch {
	case servedByUs:
		defer ln.connectionsWg.Done()
		if subtestID != 0 {
			// TODO refactor this to have the logic in one place,
			// instead of scattered through conn.go and server.go
			serverCapture := &ServerCapture{
				Capture: Capture{
					SubtestID: subtestID,
					BeginTime: startTime.UTC(),
					Frames:    []Frame{},
					HasFailed: true,
				},
				ClientIP: net.ParseIP(parseHost(remoteAddr)),
				ServerIP: net.ParseIP(parseHost(localAddr)),
			}
			capturedConn := &serverCaptureConn{
				CaptureConn:        NewCaptureConn(peekableConn, &serverCapture.Frames),
				name:               sni,
				info:               serverCapture,
				ServerCaptureReady: ln.ServerCaptureReady,
			}
			ln.newc <- capturedConn
		} else {
			ln.newc <- peekableConn
		}
	case !isTLS && ln.flashpolicyserver.IsRequest(buffer):
		log.Printf("%s / %s - handling Flash Socket Policy request", remoteAddr, localAddr)
		ln.flashpolicyserver.WriteResponse(c)
	case ln.originAddress == "":
		log.Printf("%s / %s - no upstream configured", remoteAddr, localAddr)
		if sni != "" {
			c.Write(tlsRecordUnrecognizedName)
		} else if isTLS {
			c.Write(tlsRecordHandshakeFailure)
		}
	default:
		if err := proxyConnection(peekableConn, ln.originAddress); err != nil {
			log.Printf("%s / %s - error proxying connection: %v\n", remoteAddr, localAddr, err)
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

	return c, nil
}
