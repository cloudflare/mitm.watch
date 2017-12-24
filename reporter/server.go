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
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

func (h *hostHandler) getCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if strings.ToLower(info.ServerName) == h.config.HostReporter {
		return h.reporterCert.Load()
	}

	return h.dummyCert.Load()
}

// Sets the maximum version for the test server target to TLS 1.3.
func (h *hostHandler) getConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
	if isTestHost(info.ServerName, h.config) {
		return h.tls13Config, nil
	}
	return nil, nil
}

type hostHandler struct {
	http.Handler
	reporterHandler http.Handler
	config          *Config
	tls13Config     *tls.Config
	reporterCert    *CertificateLoader
	dummyCert       *CertificateLoader
}

func isTestHost(host string, config *Config) bool {
	return strings.HasSuffix(host, config.HostSuffixIPv4) || strings.HasSuffix(host, config.HostSuffixIPv6)
}

func makeIsOurHost(db *sql.DB, config *Config) RequestClaimer {
	return func(host string) (bool, int) {
		host = strings.ToLower(host)
		if host == config.HostReporter {
			// pass to HTTP handler, handle API requests.
			return true, 0
		}
		if isTestHost(host, config) {
			// pass to HTTP handler, handling a basic response.
			// Logging is tentatively enabled.
			return true, prepareServerCapture(db, config, host)
		}
		return false, 0
	}
}

func prepareServerCapture(db *sql.DB, config *Config, host string) int {
	testID, number := parseTestHost(config, host)
	if testID == "" {
		log.Printf("Host \"%s\" is not a valid test domain, ignoring", host)
		return 0
	}
	subtestID, err := QuerySubtest(db, testID, number, config.MutableTestPeriodSecs)
	if err != nil {
		log.Printf("Failed to query subtest for \"%s\": %s", host, err)
		return 0
	}
	if subtestID == 0 {
		log.Printf("Not accepting server capture for \"%s\"", host)
		return 0
	}
	return subtestID
}

// parses a host name of the form "<testID>-<number><suffix>", returning the
// TestID and subtest number. On error, the testID is empty.
func parseTestHost(config *Config, host string) (string, int) {
	var prefix string
	switch {
	case strings.HasSuffix(host, config.HostSuffixIPv4):
		prefix = host[:len(host)-len(config.HostSuffixIPv4)]
	case strings.HasSuffix(host, config.HostSuffixIPv6):
		prefix = host[:len(host)-len(config.HostSuffixIPv6)]
	default:
		return "", 0
	}

	// testID UUID is always 36 chars followed by "-" and number.
	if len(prefix) < 36+2 || prefix[36] != '-' {
		return "", 0
	}
	testID, numberStr := prefix[0:36], prefix[37:]
	if !ValidateUUID(testID) {
		return "", 0
	}
	number, err := strconv.Atoi(numberStr)
	if err != nil || number <= 0 {
		return "", 0
	}

	return testID, number
}

func newServerCaptureReady(db *sql.DB) func(*ServerCapture) {
	return func(serverCapture *ServerCapture) {
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Failed to begin transaction: %s", err)
			return
		}
		defer func() {
			if tx != nil {
				tx.Rollback()
			}
		}()

		err = serverCapture.Create(tx)
		if err != nil {
			log.Printf("Failed to create server capture: %s", err)
			return
		}

		log.Printf("Stored server capture: %d", serverCapture.ID)
		tx.Commit()
		tx = nil
	}
}

func (h *hostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	config := h.config
	sni := strings.ToLower(r.TLS.ServerName)

	// Use SNI instead of Host header, a capture is based on the former.
	if isTestHost(sni, config) {
		w.Write([]byte("Hello world!\n"))
		return
	}

	host := strings.ToLower(parseHost(r.Host))
	if host == config.HostReporter {
		h.reporterHandler.ServeHTTP(w, r)
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
		if err := config.Update(configFile); err != nil {
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

	reporterCert := NewCertificateLoader(config.ReporterCertificate, config.ReporterPrivateKey)
	if _, err := reporterCert.Load(); err != nil {
		log.Fatalf("Failed to load reporter certificate: %s", err)
	}
	dummyCert := NewCertificateLoader(config.DummyCertificate, config.DummyPrivateKey)
	if _, err := dummyCert.Load(); err != nil {
		log.Fatalf("Failed to load dummy certificate: %s", err)
	}

	db, err := sql.Open("postgres", config.DatabaseConnInfo)
	if err != nil {
		panic(err)
	}
	if err = db.Ping(); err != nil {
		panic(err)
	}

	l, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		panic(err)
	}
	initialReadTimeout := time.Duration(config.InitialReadTimeoutSecs) * time.Second
	wl := newListener(l, initialReadTimeout, config.OriginAddress, makeIsOurHost(db, config), newServerCaptureReady(db))
	go wl.Serve()

	hostRouter := &hostHandler{
		reporterHandler: newReporter(db, config),
		config:          config,
		reporterCert:    reporterCert,
		dummyCert:       dummyCert,
	}

	tlsConfig := &tls.Config{
		GetCertificate:     hostRouter.getCertificate,
		GetConfigForClient: hostRouter.getConfigForClient,
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

	hostRouter.tls13Config = tlsConfig.Clone()
	hostRouter.tls13Config.MaxVersion = tls.VersionTLS13

	server := &http.Server{
		Handler:      hostRouter,
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 180 * time.Second,
	}
	err = server.ServeTLS(wl, "", "")
	if err != nil {
		log.Printf("ServeTLS failed: %v\n", err)
	}
}
