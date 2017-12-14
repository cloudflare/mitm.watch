package main

import (
	"crypto/tls"
	"database/sql"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	_ "github.com/lib/pq"
)

func makeGetCertificate(config *Config) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if strings.ToLower(info.ServerName) == config.HostReporter {
			// TODO load trusted, user-facing certificate
		}

		// TODO load (possibly untrusted / self-signed) certificate
		cert, err := tls.LoadX509KeyPair("server.pem", "server.pem")
		return &cert, err
	}
}

type hostHandler struct {
	http.Handler
	reporterHandler http.Handler
	config          *Config
}

func makeIsOurHost(config *Config) RequestClaimer {
	return func(host string) (bool, bool) {
		host = strings.ToLower(host)
		if host == config.HostReporter {
			// pass to HTTP handler, handle API requests.
			return true, false
		}
		if strings.HasSuffix(host, config.HostSuffixIPv4) || strings.HasSuffix(host, config.HostSuffixIPv6) {
			// pass to HTTP handler, handling a basic response.
			// Logging is tentatively enabled.
			return true, true
		}
		return false, false
	}
}

func (h *hostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	config := h.config
	host := strings.ToLower(parseHost(r.Host))

	if host == config.HostReporter {
		h.reporterHandler.ServeHTTP(w, r)
		return
	}
	if strings.HasSuffix(host, config.HostSuffixIPv4) || strings.HasSuffix(host, config.HostSuffixIPv6) {
		// magic response that should be checked for by the client
		w.Write([]byte("Hello world!\n"))
		return
	}

	http.Error(w, "site is not configured", http.StatusNotFound)
}

func main() {
	config := &defaultConfig
	db, err := sql.Open("postgres", config.DatabaseConnInfo)
	if err != nil {
		panic(err)
	}
	if err = db.Ping(); err != nil {
		panic(err)
	}

	address := ":4433"
	l, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	wl := newListener(l, config.SessionTimeout, config.OriginAddress, makeIsOurHost(config))

	hostRouter := &hostHandler{
		reporterHandler: newReporter(db, config),
		config:          config,
	}

	tlsConfig := &tls.Config{
		GetCertificate: makeGetCertificate(config),
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
