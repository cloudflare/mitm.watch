package flashsocketpolicy

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyfile"
)

const serverType = "flashsocketpolicy"

var directives = []string{
	"ports",
}

func init() {
	caddy.RegisterServerType(serverType, caddy.ServerType{
		Directives: func() []string { return directives },
		DefaultInput: func() caddy.Input {
			return caddy.CaddyfileInput{
				ServerTypeName: serverType,
			}
		},
		NewContext: newContext,
	})

	caddy.RegisterPlugin("ports", caddy.Plugin{
		ServerType: serverType,
		Action:     setupPorts,
	})
}

func setupPorts(c *caddy.Controller) error {
	p := c.Context().(*policyContext)
	siteConfig := p.siteConfigs[c.Key]
	for c.Next() {
		if !c.NextArg() {
			// missing port
			return c.Err("ports argument is required")
		}
		toPorts := c.Val()
		domain := "*"
		if c.NextArg() {
			domain = c.Val()
		}
		if c.NextArg() {
			return c.ArgErr()
		}
		line := fmt.Sprintf(`<allow-access-from domain="%s" to-ports="%s" />`+"\n", domain, toPorts)
		siteConfig.rules = append(siteConfig.rules, line)
	}
	return nil
}

func newContext() caddy.Context {
	return &policyContext{siteConfigs: make(map[string]*siteConfig)}
}

type siteConfig struct {
	listenAddress string
	rules         []string
}

type policyContext struct {
	// socket policy for each site
	siteConfigs map[string]*siteConfig
}

func (p *policyContext) InspectServerBlocks(_ string, serverBlocks []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error) {
	// Parse a config like:
	// flashsocketpolicy host:port {
	//     // allow access to port 443 from any domain
	//     ports 443
	//     ports 443 *
	//     // allow access to multiple ports
	//     ports 80,443 *.example.com
	//     // allow access to a range of ports
	//     ports 4430-4433 *.example.net
	// }
	addressToKey := make(map[string]string)
	for _, sb := range serverBlocks {
		for _, key := range sb.Keys {
			host, port, err := net.SplitHostPort(key)
			if err != nil {
				host = key
				port = "843"
			}
			addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
			if err != nil {
				return nil, err
			}
			addrstr := addr.String()
			if otherKey := addressToKey[addrstr]; otherKey != "" {
				return nil, fmt.Errorf("duplicate address %v for label %v, saw %v before", addrstr, key, otherKey)
			}
			addressToKey[addrstr] = key
			p.siteConfigs[key] = &siteConfig{listenAddress: addrstr}
		}
	}
	return serverBlocks, nil
}

func (p *policyContext) MakeServers() ([]caddy.Server, error) {
	var servers []caddy.Server
	for _, config := range p.siteConfigs {
		server := newPolicyServer(config)
		servers = append(servers, server)
	}
	return servers, nil
}

type policyServer struct {
	address string
	// response to policy request
	response []byte
}

func newPolicyServer(config *siteConfig) *policyServer {
	var buffer bytes.Buffer
	buffer.WriteString(`<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
`)
	for _, line := range config.rules {
		buffer.WriteString(line)
	}
	buffer.WriteString("</cross-domain-policy>\n")
	return &policyServer{
		address:  config.listenAddress,
		response: buffer.Bytes(),
	}
}

func (*policyServer) ListenPacket() (net.PacketConn, error) {
	return nil, nil
}

func (*policyServer) ServePacket(net.PacketConn) error {
	return nil
}

func (s *policyServer) Listen() (net.Listener, error) {
	log.Println("Listening on", s.address)
	return net.Listen("tcp", s.address)
}

func (s *policyServer) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *policyServer) handle(conn net.Conn) {
	defer conn.Close()
	receivedLine := make([]byte, len(policyRequestLine))
	n, _ := conn.Read(receivedLine)
	if n == len(receivedLine) && bytes.Equal(receivedLine, policyRequestLine) {
		conn.Write(s.response)
	}
}

var policyRequestLine = []byte("<policy-file-request/>\000")
