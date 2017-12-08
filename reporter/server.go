package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// configuration used in listener.go
	originAddress  = ""
	sessionTimeout = 60 * time.Second

	// Host name (suffix) for various purposes.
	hostReporter   = "l.ls-l.info"   // Reporter API
	hostSuffixIPv4 = ".l4.ls-l.info" // IPv4 tests
	hostSuffixIPv6 = ".l6.ls-l.info" // IPv6 tests
)

func getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	// TODO select certificate based on host
	cert, err := tls.LoadX509KeyPair("server.pem", "server.pem")
	return &cert, err
}

type hostHandler struct {
	http.Handler
	reporterHandler http.Handler
}

func (h *hostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip port number from host
	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = r.Host
	}
	host = strings.ToLower(host)

	if host == hostReporter {
		// TODO implement reporter handler
		//h.reporterHandler.ServeHTTP(w, r)
		return
	}
	if strings.HasSuffix(host, hostSuffixIPv4) || strings.HasSuffix(host, hostSuffixIPv6) {
		// magic response that should be checked for by the client
		w.Write([]byte("Hello world!\n"))
		return
	}

	http.Error(w, "site is not configured", http.StatusNotFound)
}

func main() {
	address := ":4433"
	l, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	wl := newListener(l)

	hostRouter := &hostHandler{}

	tlsConfig := &tls.Config{
		GetCertificate: getCertificate,
	}

	if keylogFilename := os.Getenv("SSLKEYLOGFILE"); keylogFilename != "" {
		kw, err := os.OpenFile(keylogFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			log.Printf("failed to write key log file: %v\n", err)
		} else {
			log.Printf("Enabled keylogging to %v\n", keylogFilename)
			defer kw.Close()
			tlsConfig.KeyLogWriter = kw
		}
	}

	server := &http.Server{
		Handler:   hostRouter,
		TLSConfig: tlsConfig,
	}
	err = server.ServeTLS(wl, "", "")
	if err != nil {
		log.Printf("ServeTLS failed: %v\n", err)
	}
}
