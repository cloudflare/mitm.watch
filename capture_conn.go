// a net.Conn implementation which records all of its traffic until told
// otherwise.
package main

import (
	"net"
	"time"
)

type CaptureConn struct {
	net.Conn

	frames *[]Frame
}

// Wrap an existing connection, logging data to the given frames array.
func NewCaptureConn(conn net.Conn, frames *[]Frame) *CaptureConn {
	return &CaptureConn{conn, frames}
}

func (c *CaptureConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.captureFrame(b[:n], true)
	return n, err
}

func (c *CaptureConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.captureFrame(b[:n], false)
	return n, err
}

func (c *CaptureConn) captureFrame(b []byte, isRead bool) {
	if len(b) == 0 || c.frames == nil {
		return
	}
	packetTime := time.Now().UTC()
	data := make([]byte, len(b))
	copy(data, b)
	frame := Frame{
		Data:   data,
		IsRead: isRead,
		Time:   packetTime,
	}
	*c.frames = append(*c.frames, frame)
}

func (c *CaptureConn) StopCapture() {
	c.frames = nil
}
