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

var (
	once      sync.Once
	socketApi *js.Object // the flash object reference
)

type keyLogPrinter struct{}

func (*keyLogPrinter) Write(line []byte) (int, error) {
	fmt.Println(string(line))
	return len(line), nil
}

func main() {
	once.Do(initSocketApi)
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
	fmt.Printf("%s", response[:n])
}

func socketCall(name string, args ...interface{}) (interface{}, error) {
	res := socketApi.Call(name, args...)
	if socketApi == nil {
		return nil, errors.New("Flash is not ready")
	}
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
	for i := 0; i < 100; i++ {
		socketApi = getSocketApi()
		if socketApi == nil {
			time.Sleep(100 * time.Millisecond)
		} else {
			break
		}
	}

	if socketApi == nil {
		panic("Failed to load Flash plugin")
	}

	// TODO change this debug into actual channel updates
	socketApi.Call("subscribe", "console.log")
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
	socketId int // the socket ID
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
	conn := &Conn{socketId: socketId}
	// TODO call destroy when the socket ID is no longer needed?
	if err = conn.connect(host, port); err != nil {
		return nil, err
	}
	log.Println("connected!")
	return conn, nil
}

// loadPolicy tries to authorize socket connections to the given host. The given
// port must respond with a Flash socket policy file. If not called, Flash will
// only try to poke the master policy server at port 843.
func loadPolicy(host, port string) error {
	_, err := socketCall("loadPolicyFile", "xmlsocket://"+host+":"+port)
	return err
}

func (s *Conn) connect(host, port string) error {
	// TODO make this configurable
	if err := loadPolicy(host, "8001"); err != nil {
		return err
	}

	fmt.Println("connect", s.socketId, host, port)
	_, err := socketCall("connect", s.socketId, host, port)
	if err != nil {
		return err
	}

	// TODO connect can fail with ioError 2031 when nothing is listening on
	// the port. Catch this to avoid a securityError 2048 later.
	// TODO goroutine that checks event listener?
	// TODO error out when error event was emitted before
	for i := 0; i < 20; i++ {
		value, err := socketCall("isConnected", s.socketId)
		if connected, ok := value.(bool); ok {
			if connected {
				return nil
			} else {
				return err
			}
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return errors.New("Not connected")
}

func (s *Conn) Read(b []byte) (n int, err error) {
	// TODO Read is non-blocking, maybe register event listener?
	b64Data, err := socketCallString("receive", s.socketId, len(b))
	if err != nil {
		// TODO detect EOF
		return 0, err
	}
	if b64Data == "" {
		// TODO wait for data to become available
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
	return err
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
