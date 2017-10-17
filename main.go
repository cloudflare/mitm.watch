package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gopherjs/gopherjs/js"
)

var (
	once      sync.Once
	socketApi *js.Object // the flash object reference

	// List of connections (for dispatching events)
	connections       map[int]*Conn
	connectionsRWLock sync.RWMutex
)

// Experiments configuration
type Experiment struct {
	Domain   string
	IPv6     bool
	Version  uint16
	Result   string
	Failed   bool
	Expected string // expected error message
}

type keyLogPrinter struct{}

func (*keyLogPrinter) Write(line []byte) (int, error) {
	fmt.Println(string(line))
	return len(line), nil
}

func updateStatus(status string) {
	if fn := js.Global.Get("updateStatus"); fn != js.Undefined {
		go func() {
			fn.Invoke(status)
		}()
	}
}

func addExperiment(exp *Experiment) {
	if fn := js.Global.Get("addExperiment"); fn != js.Undefined {
		go func() {
			fn.Invoke(exp)
		}()
	}
}

func updateExperiment(i int, exp *Experiment) {
	if fn := js.Global.Get("updateExperiment"); fn != js.Undefined {
		go func() {
			fn.Invoke(i, exp)
		}()
	}
}

func main() {
	updateStatus("booting")
	once.Do(initSocketApi)
	updateStatus("booted")

	experiments := []*Experiment{
		{Domain: ipv4Domain, Version: tls.VersionTLS12},
		{Domain: ipv4Domain, Version: tls.VersionTLS13},
		{Domain: ipv6Domain, IPv6: true, Version: tls.VersionTLS12},
		{Domain: ipv6Domain, IPv6: true, Version: tls.VersionTLS13},
		// should fail as SSL 3.0 is disabled
		{Domain: ipv4Domain, Version: tls.VersionSSL30, Expected: "remote error: tls: protocol version not supported"},
		// should fail as the host does not exist
		{Domain: noDomain, Version: tls.VersionTLS12, Expected: "connection timed out"},
	}
	// randomize addresses (for easier tracking purposes)
	for _, exp := range experiments {
		var randBytes [16]byte
		_, err := rand.Read(randBytes[:])
		if err != nil {
			panic("random failed")
		}
		exp.Domain = fmt.Sprintf("%x.%s", randBytes, exp.Domain)
		// display in UI
		addExperiment(exp)
	}
	var wg sync.WaitGroup
	for i, exp := range experiments {
		i := i
		exp := exp
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := tryTLS(exp.Domain, exp.Version)
			if err != nil {
				exp.Result = err.Error()
				exp.Failed = exp.Expected != err.Error()
			} else {
				exp.Result = response
				exp.Failed = exp.Expected != ""
			}
			// display in UI
			updateExperiment(i, exp)
		}()
	}
	wg.Wait()
	for _, exp := range experiments {
		// Calling console.log for now because it hides private fields.
		js.Global.Get("console").Call("log", exp)
	}
}

func tryTLS(domain string, version uint16) (string, error) {
	conn, err := DialTCP("tcp", net.JoinHostPort(domain, tlsPort))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	tls_config := &tls.Config{
		ServerName:   domain,
		KeyLogWriter: &keyLogPrinter{},
		MinVersion:   version,
		MaxVersion:   version,
	}
	var rootCAs *x509.CertPool
	if rootCAs != nil {
		tls_config.RootCAs = rootCAs
	} else {
		tls_config.InsecureSkipVerify = true
	}

	tls_conn := tls.Client(conn, tls_config)
	n, err := tls_conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if err != nil {
		return "", err
	}
	response := make([]byte, 1024)
	n, err = tls_conn.Read(response)
	if err != nil {
		return "", err
	}
	fmt.Println("Response:")
	fmt.Printf("%s", response[:n])
	return string(response[:n]), nil
}

func socketCall(name string, args ...interface{}) (interface{}, error) {
	if socketApi == nil {
		return nil, errors.New("Flash is not ready")
	}
	res := socketApi.Call(name, args...)
	var value interface{}
	if valueObj := res.Get("value"); valueObj != js.Undefined {
		value = valueObj.Interface()
	}
	var err error
	if errObj := res.Get("error"); errObj != js.Undefined {
		err = errors.New(errObj.String())
	}
	return value, err
}

func socketCallInt(name string, args ...interface{}) (int, error) {
	value, err := socketCall(name, args...)
	v, ok := value.(float64)
	if err == nil && !ok {
		err = errors.New("wanted int as remote type")
	}
	return int(v), err
}

func socketCallString(name string, args ...interface{}) (string, error) {
	value, err := socketCall(name, args...)
	v, ok := value.(string)
	if err == nil && !ok {
		err = errors.New("wanted string as remote type")
	}
	return v, err
}

func initSocketApi() {
	// wait for the SWF to become ready
	for {
		socketApi = getSocketApi()
		if socketApi == nil {
			time.Sleep(100 * time.Millisecond)
		} else {
			break
		}
	}

	socketApi.Call("subscribe", "console.log") // TODO remove debug

	connections = make(map[int]*Conn)
	js.Global.Set("socketApiListener", js.MakeFunc(handleEvent))
	socketApi.Call("subscribe", "socketApiListener")
}

func getSocketApi() *js.Object {
	sp := js.Global.Get("document").Call("getElementById", "socketApi")
	initFunc := sp.Get("loadPolicyFile")
	if initFunc == js.Undefined {
		return nil
	}
	return sp
}

// An open socket
type Conn struct {
	socketId     int        // the socket ID
	ioResult     chan error // result of connect/read attempt
	readLock     sync.Mutex // mutex to protect connect/read
	readDeadline time.Time
	readTimer    *time.Timer
}

type socketEvent struct {
	socketId       int
	eventType      string
	errorMessage   string
	bytesAvailable uint
}

// handleEvent processes events from the Flash socket API.
func handleEvent(this *js.Object, arguments []*js.Object) interface{} {
	o := arguments[0]
	socketEvent := socketEvent{
		socketId:  o.Get("socket").Int(),
		eventType: o.Get("type").String(),
	}
	if v, ok := o.Get("error").Interface().(string); ok {
		socketEvent.errorMessage = v
	}
	if v, ok := o.Get("bytesAvailable").Interface().(float64); ok {
		socketEvent.bytesAvailable = uint(v)
	}
	if conn := getSocket(socketEvent.socketId); conn != nil {
		go conn.handleSocketEvent(socketEvent)
	}
	return nil
}

func registerSocket(conn *Conn) {
	connectionsRWLock.Lock()
	defer connectionsRWLock.Unlock()
	connections[conn.socketId] = conn
}

func getSocket(socketId int) *Conn {
	connectionsRWLock.RLock()
	defer connectionsRWLock.RUnlock()
	return connections[socketId]
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

	if socketApi == nil {
		return nil, errors.New("Flash is not ready")
	}
	socketId, err := socketCallInt("create")
	if err != nil {
		return nil, err
	}
	conn := &Conn{
		socketId: socketId,
		ioResult: make(chan error, 1),
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	registerSocket(conn)
	if err = conn.connect(host, port); err != nil {
		socketCall("destroy", socketId)
		return nil, err
	}
	return conn, nil
}

func (conn *Conn) handleSocketEvent(socketEvent socketEvent) {
	switch socketEvent.eventType {
	case "connect":
		select {
		case conn.ioResult <- nil:
		default:
		}

	case "ioError", "securityError":
		err := errors.New(socketEvent.errorMessage)
		// do not block in case of multiple errors.
		select {
		case conn.ioResult <- err:
		default:
		}

	case "socketData":
		// inform of available data, non-blocking
		select {
		case conn.ioResult <- nil:
		default:
		}

	case "close":
		select {
		case conn.ioResult <- io.EOF:
		default:
		}
	}
}

// loadPolicy tries to authorize socket connections to the given host. The given
// port must respond with a Flash socket policy file. If not called, Flash will
// only try to poke the master policy server at port 843.
func loadPolicy(host, port string) error {
	_, err := socketCall("loadPolicyFile", "xmlsocket://"+host+":"+port)
	return err
}

func (s *Conn) readTimeout() <-chan time.Time {
	var d time.Duration
	if s.readDeadline.IsZero() {
		// Returning nil here would result in a "fatal error: all
		// goroutines are asleep - deadlock!" error because indeed no
		// goroutines are active (we rely on Flash callbacks to wake
		// us). As a workaround, use some point "far" in the future.
		d = 48 * time.Hour
	} else {
		d = s.readDeadline.Sub(time.Now())
	}
	if s.readTimer == nil {
		s.readTimer = time.NewTimer(d)
	} else {
		// under s.readLock, so we got exclusive access here.
		if !s.readTimer.Stop() {
			<-s.readTimer.C
		}
		s.readTimer.Reset(d)
	}
	return s.readTimer.C
}

func (s *Conn) connect(host, port string) error {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	_, err := socketCall("connect", s.socketId, host, port)
	if err != nil {
		return err
	}

	select {
	case err = <-s.ioResult:
		return err
	case <-s.readTimeout():
		return errors.New("connection timed out")
	}
}

// readData tries to read at most n bytes from the socket, blocking until bytes
// become available.
func (s *Conn) readData(n int) (string, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()
	var err error

	// clear past data results, then try to read data and otherwise wait.
	select {
	case err = <-s.ioResult:
	default:
	}
	b64Data, err := socketCallString("receive", s.socketId, n)
	if err == nil && b64Data == "" {
		// no data available, block until there is data
		select {
		case err = <-s.ioResult:
			if err != io.EOF {
				b64Data, err = socketCallString("receive", s.socketId, n)
			}

		case <-s.readTimeout():
			err = errors.New("read timed out")
		}
	}
	// could happen if read was attempted after EOF
	if err != nil && err.Error() == "Error: socket is closed" {
		err = io.EOF
	}
	return b64Data, err
}

func (s *Conn) Read(b []byte) (n int, err error) {
	b64Data, err := s.readData(len(b))
	if err != nil {
		return 0, err
	}
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return 0, err
	}
	copy(b, data)
	return len(data), nil
}

func (s *Conn) Write(b []byte) (int, error) {
	b64Data := base64.StdEncoding.EncodeToString(b)
	_, err := socketCall("send", s.socketId, b64Data)
	if err != nil {
		return 0, err
	} else {
		return len(b), nil
	}
}

func (s *Conn) Close() error {
	_, err := socketCall("close", s.socketId)
	socketCall("destroy", s.socketId)
	return err
}

func (s *Conn) LocalAddr() net.Addr {
	return nil
}

func (s *Conn) RemoteAddr() net.Addr {
	return nil
}

func (s *Conn) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

func (s *Conn) SetReadDeadline(t time.Time) error {
	s.readDeadline = t
	return nil
}

func (s *Conn) SetWriteDeadline(t time.Time) error {
	return errors.New("write deadlines are not supported")
}
