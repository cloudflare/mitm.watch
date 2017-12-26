package main

import (
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
	Domain  string
	IPv6    bool
	Version uint16
	Result  string
	Failed  bool
}

type keyLogPrinter struct {
	lines string
}

func (keylog *keyLogPrinter) Write(line []byte) (int, error) {
	lineStr := string(line)
	keylog.lines += lineStr + "\n"
	fmt.Print(lineStr)
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

func specToDomain(testId string, spec SubtestSpec) string {
	domain := ipv4Domain
	if spec.IsIPv6 {
		domain = ipv6Domain
	}
	return fmt.Sprintf("%s-%d.%s", testId, spec.Number, domain)
}

func gatherTests(verbose bool) (string, []SubtestSpec, error) {
	testRequest := createTestRequest{
		// TODO populate client version
		ClientVersion: "TEST",
		FlashVersion:  "",
		UserAgent:     js.Global.Get("navigator").Get("userAgent").String(),
	}
	return CreateTest(testRequest, !verbose)
}

func runTests(testId string, specs []SubtestSpec, verbose bool) {
	experiments := make([]Experiment, len(specs))
	var wg sync.WaitGroup
	for i, spec := range specs {
		i := i
		spec := spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			domain := specToDomain(testId, spec)
			result := clientResult{
				BeginTime: time.Now().UTC(),
				Frames:    []Frame{},
				HasFailed: true,
			}
			response, err := tryTLS(domain, spec.MaxTLSVersion, &result)
			result.EndTime = time.Now().UTC()
			if verbose {
				go func() {
					err := SaveTestResult(testId, spec.Number, result)
					if err != nil {
						js.Global.Get("console").Call("log",
							fmt.Sprintf("SaveTestResult(%s, %d) failed: %s",
								testId, spec.Number, err))
					}
				}()
			}

			// TODO rewrite this, remove Experiment struct.
			// Currently only here to avoid changing frontend
			exp := &experiments[i]
			exp.Domain = domain
			exp.IPv6 = spec.IsIPv6
			exp.Version = spec.MaxTLSVersion
			if err != nil {
				exp.Result = err.Error()
				exp.Failed = true
			} else {
				exp.Result = response
				exp.Failed = false
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

// startTests retrieves test cases, executes them and optionally submits test
// results back to the server.
func StartTests(verbose bool) {
	testId, specs, err := gatherTests(verbose)
	if err != nil {
		// TODO this could be a network error, show message to user
		panic(err)
	}

	// display tests in UI
	for _, spec := range specs {
		exp := &Experiment{
			Domain:  specToDomain(testId, spec),
			IPv6:    spec.IsIPv6,
			Version: spec.MaxTLSVersion,
		}
		addExperiment(exp)
	}

	runTests(testId, specs, verbose)
}

type JsApi struct{}

func (*JsApi) StartTests(verbose bool) {
	go StartTests(verbose)
}

func registerJSApi() {
	jsApi := &JsApi{}
	js.Global.Set("jssock", js.MakeWrapper(jsApi))
}

func main() {
	updateStatus("booting")
	once.Do(initSocketApi)
	registerJSApi()
	updateStatus("booted")
}

func tryTLS(domain string, version uint16, result *clientResult) (string, error) {
	conn, err := DialTCP("tcp", net.JoinHostPort(domain, tlsPort))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	keylog := &keyLogPrinter{}
	tls_config := &tls.Config{
		ServerName:   domain,
		KeyLogWriter: keylog,
		MinVersion:   version,
		MaxVersion:   version,
	}
	var rootCAs *x509.CertPool
	if rootCAs != nil {
		tls_config.RootCAs = rootCAs
	} else {
		tls_config.InsecureSkipVerify = true
	}

	tappedConn := NewCaptureConn(conn, &result.Frames)
	tls_conn := tls.Client(tappedConn, tls_config)

	if err := tls_conn.Handshake(); err != nil {
		return "", err
	}
	// Handshake successful, store version and keys
	result.ActualTLSVersion = tls_conn.ConnectionState().Version
	result.KeyLog = keylog.lines

	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", domain)
	n, err := tls_conn.Write([]byte(request))
	if err != nil {
		return "", err
	}
	response := make([]byte, 1024)
	n, err = tls_conn.Read(response)
	if n == 0 {
		return "", err
	}
	fmt.Println("Response:")
	fmt.Printf("%s", response[:n])
	result.HasFailed = false
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
	conn.SetDeadline(time.Now().Add(30 * time.Second))
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
