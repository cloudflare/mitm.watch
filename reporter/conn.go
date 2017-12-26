// Various net.Conn implementations to support peeking or capturing data.
package main

import (
	"io"
	"net"
	"sync"
	"time"
)

// A net.Conn implementation which allows for buffering the initial read such
// that it can be peeked into without consuming it in the actual read buffer.
type conn struct {
	net.Conn
	readBuffer []byte
	readLock   sync.Mutex
}

func NewPeekableConn(c net.Conn) *conn {
	return &conn{Conn: c}
}

// peek for at most n bytes. The returned buffer is internal and should not be
// modified. Should be called once with no concurrent readers.
func (c *conn) peek(n int) ([]byte, error) {
	c.readLock.Lock()
	defer c.readLock.Unlock()
	if c.readBuffer != nil {
		panic("peeked more than once")
	}
	buffer := make([]byte, n)
	realSize, err := c.Conn.Read(buffer)
	if realSize > 0 {
		c.readBuffer = buffer[:realSize]
	}
	return c.readBuffer, err
}

// Reads data from the connection. If data was peeked before, that data is read
// first.
func (c *conn) Read(b []byte) (int, error) {
	c.readLock.Lock()
	if c.readBuffer != nil {
		defer c.readLock.Unlock()
		n := copy(b, c.readBuffer)
		if len(b) < len(c.readBuffer) {
			c.readBuffer = c.readBuffer[len(b):]
		} else {
			c.readBuffer = nil
		}
		return n, nil
	} else {
		c.readLock.Unlock()
	}
	return c.Conn.Read(b)
}

type serverCaptureConn struct {
	*CaptureConn
	name               string
	info               *ServerCapture
	ServerCaptureReady ServerCaptureNotifier
}

func (c *serverCaptureConn) Close() error {
	err := c.CaptureConn.Close()
	if c.CaptureConn.StopCapture() {
		c.info.EndTime = time.Now().UTC()
		c.ServerCaptureReady(c.name, c.info)
	}
	return err
}

func (c *serverCaptureConn) SetActualTLSVersion(version uint16) {
	c.info.ActualTLSVersion = version
	c.info.HasFailed = false
}

type serverKeyLog struct {
	lines *string
	next  io.Writer
}

func (l serverKeyLog) Write(line []byte) (int, error) {
	*l.lines += string(line)
	if l.next != nil {
		return l.next.Write(line)
	}
	return len(line), nil
}
