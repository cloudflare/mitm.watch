package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gopherjs/gopherjs/js"
)

var initLock sync.Mutex
var inited bool

type keyLogPrinter struct{}

func (*keyLogPrinter) Write(line []byte) (int, error) {
	fmt.Println(string(line))
	return len(line), nil
}

func main() {
	initOnce()
	conn, err := DialTCP("tcp", "localhost:4433")
	if err != nil {
		panic(err)
	}
	tls_config := &tls.Config{
		ServerName:   "localhost",
		KeyLogWriter: &keyLogPrinter{},
		MaxVersion:   tls.VersionTLS13,
	}
	var rootCAs *x509.CertPool
	if rootCAs != nil {
		tls_config.RootCAs = rootCAs
	} else {
		tls_config.InsecureSkipVerify = true
	}

	tls_conn := tls.Client(conn, tls_config)
	fmt.Println(tls_conn)
	n, err := tls_conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if err != nil {
		panic(err)
	}
	response := make([]byte, 1024)
	n, err = tls_conn.Read(response)
	if err != nil {
		panic(err)
	}
	fmt.Println("Response:")
	fmt.Println(response[:n])
}

func initOnce() {
	initLock.Lock()
	defer initLock.Unlock()
	if inited {
		return
	}

	var socketPool *js.Object
	// wait for the SWF to become ready
	for i := 0; i < 100; i++ {
		socketPool = getSocketPool()
		if socketPool == nil {
			time.Sleep(100 * time.Millisecond)
		} else {
			break
		}
	}

	if socketPool == nil {
		panic("Failed to load Flash plugin")
	}

	socketPool.Call("init")
	registerListeners(socketPool)
}

func getSocketPool() *js.Object {
	sp := js.Global.Get("document").Call("getElementById", "socketPool")
	initFunc := sp.Get("init")
	if initFunc == js.Undefined {
		return nil
	}
	return sp
}

// registerListeners adds some debug logging for the Flash binary.
func registerListeners(socketPool *js.Object) {
	events := [...]string{"connect", "close", "ioError", "securityError", "socketData"}
	for _, event := range events {
		socketPool.Call("subscribe", event, "console.log")
	}
}

// An open socket
type Conn struct {
	socketPool *js.Object // the flash object reference
	socketId   string     // the socket ID
}

func DialTCP(network, address string) (*Conn, error) {
	// TODO accept other TCP variants?
	if network != "tcp" {
		return nil, errors.New("Unsupported network")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	socketPool := getSocketPool()
	if socketPool == nil {
		return nil, errors.New("Flash is not ready")
	}
	socketId := socketPool.Call("create").String()
	conn := &Conn{socketPool: socketPool, socketId: socketId}
	// TODO call destroy when the socket ID is no longer needed?
	if err = conn.connect(host, port); err != nil {
		return nil, err
	}
	log.Println("connected!")
	return conn, nil
}

func (s *Conn) connect(host, port string) error {
	// TODO make this configurable.
	// Service that responds with Flash socket policy file (CANNOT BE HTTP(S)!)
	policyPort := 8001

	fmt.Println("connect", s.socketId, host, port, policyPort)
	s.socketPool.Call("connect", s.socketId, host, port, policyPort)

	// TODO connect can fail with ioError 2031 when nothing is listening on
	// the port. Catch this to avoid a securityError 2048 later.
	// TODO goroutine that checks event listener?
	// TODO error out when error event was emitted before
	for i := 0; i < 20; i++ {
		ok := s.socketPool.Call("isConnected", s.socketId).Bool()
		if ok {
			return nil
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return errors.New("Not connected")
}

func (s *Conn) Read(b []byte) (n int, err error) {
	// TODO Read is non-blocking, maybe register event listener?
	result := s.socketPool.Call("receive", s.socketId, len(b))
	b64DataWrapped := result.Get("rval")
	if b64DataWrapped == js.Undefined {
		return 0, errors.New("recv failed")
	}
	// Socket might not be ready, so read it ASAP
	data, err := base64.StdEncoding.DecodeString(b64DataWrapped.String())
	if err != nil {
		return 0, err
	}
	copy(b, data)
	return len(data), nil
}

func (s *Conn) Write(b []byte) (n int, err error) {
	b64Data := base64.StdEncoding.EncodeToString(b)
	result := s.socketPool.Call("send", s.socketId, b64Data).Bool()
	if result {
		return n, nil
	} else {
		return 0, errors.New("Write error")
	}
}

func (s *Conn) Close() error {
	s.socketPool.Call("close", s.socketId)
	return nil
}

func (s *Conn) LocalAddr() net.Addr {
	return nil
}

func (s *Conn) RemoteAddr() net.Addr {
	return nil
}

func (s *Conn) SetDeadline(t time.Time) error {
	return nil
}

func (s *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}
