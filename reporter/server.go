package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

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

var errExit = errors.New("exit normally")

func parseArgs(config *Config) error {
	var configFile, configFileOut string

	flag.StringVar(&configFile, "config", "", "Configuration file (JSON)")
	flag.StringVar(&configFileOut, "writeconfig", "", "Write updated configuration file and exit")

	flag.Parse()

	if configFile != "" {
		file, err := os.Open(configFile)
		if err != nil {
			return err
		}
		defer file.Close()
		dec := json.NewDecoder(file)
		if err = dec.Decode(config); err != nil {
			return err
		}
	}

	if configFileOut != "" {
		file, err := os.OpenFile(configFileOut, os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return err
		}
		defer file.Close()
		enc := json.NewEncoder(file)
		enc.SetIndent("", "    ")
		if err = enc.Encode(config); err != nil {
			return err
		}
		return errExit
	}

	return nil
}

func main() {
	config := &defaultConfig
	if err := parseArgs(config); err != nil {
		if err != errExit {
			panic(err)
		}
		return
	}

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
	sessionTimeout := time.Duration(config.SessionTimeoutSecs) * time.Second
	wl := newListener(l, sessionTimeout, config.OriginAddress, makeIsOurHost(config))

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
