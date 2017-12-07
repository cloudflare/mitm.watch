package main

import (
	"io"
	"net"
	"sync"
)

// proxy all traffic between the connection and an upstream.
func proxyConnection(c net.Conn, upstreamAddr string) error {
	upC, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		return err
	}
	wg := sync.WaitGroup{}
	wg.Add(2)

	// to upstream
	go func() {
		io.Copy(upC, c)
		wg.Done()
	}()
	// from upstream
	go func() {
		io.Copy(c, upC)
		wg.Done()
	}()

	wg.Wait()
	return nil
}
