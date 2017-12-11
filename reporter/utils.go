package main

import (
	"crypto/rand"
	"fmt"
	"net"
)

// GenerateUUIDv4 creates a v4 UUID which is derives from random numbers.
func GenerateUUIDv4() string {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		panic("rand.Read should always return data")
	}
	// UUID version: 4 (encode as 0b0100...)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// UUID variant: 1 (encode as 0b10...)
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	// Format: 4-2-2-2-6
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// parseHost strips any port number from a host, returning just the host part.
func parseHost(host string) string {
	realHost, _, _ := net.SplitHostPort(host)
	if realHost != "" {
		return realHost
	}
	return host
}
