package main

import (
	"bytes"
	"fmt"
	"io"
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
