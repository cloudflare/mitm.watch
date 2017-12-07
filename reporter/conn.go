package main

import (
	"net"
)

type conn struct {
	net.Conn
	readBuffer []byte
}

func wrapConn(c net.Conn) *conn {
	return &conn{c, nil}
}

// peek for at most n bytes. The returned buffer is internal and should not be
// modified. Should be called once with no concurrent readers.
func (c *conn) peek(n int) ([]byte, error) {
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
// first and no concurrent readers are allowed.
func (c *conn) Read(b []byte) (int, error) {
	if c.readBuffer != nil {
		n := copy(b, c.readBuffer)
		if len(b) < len(c.readBuffer) {
			c.readBuffer = c.readBuffer[len(b):]
		} else {
			c.readBuffer = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
}
