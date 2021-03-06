package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

var policyRequestLine = []byte("<policy-file-request/>\000")

type FlashPolicyServer struct {
	response []byte
}

type FlashPolicyRule struct {
	FromDomain string
	ToPorts    string // a list of port ranges such as "443" or "80,4430-4433"
}

func NewFlashPolicyServer(rules []FlashPolicyRule) *FlashPolicyServer {
	var buffer bytes.Buffer
	buffer.WriteString(`<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
`)
	for _, rule := range rules {
		line := fmt.Sprintf(`<allow-access-from domain="%s" to-ports="%s" />`+"\n", rule.FromDomain, rule.ToPorts)
		buffer.WriteString(line)
	}
	buffer.WriteString("</cross-domain-policy>\n")
	return &FlashPolicyServer{
		response: buffer.Bytes(),
	}
}

func (*FlashPolicyServer) IsRequest(buffer []byte) bool {
	return bytes.Equal(policyRequestLine, buffer)
}

func (fsp *FlashPolicyServer) WriteResponse(w io.Writer) {
	w.Write(fsp.response)
}

func (fsp *FlashPolicyServer) Serve(ln net.Listener) error {
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		c, err := ln.Accept()
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
				log.Printf("FlashPolicyServer: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		go fsp.handleConnection(c)
	}
}

func (fsp *FlashPolicyServer) handleConnection(c net.Conn) {
	defer c.Close()
	receivedLine := make([]byte, len(policyRequestLine))
	n, _ := c.Read(receivedLine)
	if n == len(receivedLine) && bytes.Equal(receivedLine, policyRequestLine) {
		log.Printf("FlashPolicyServer: request from %s to %s", c.RemoteAddr().String(), c.LocalAddr().String())
		c.Write(fsp.response)
	}
}
