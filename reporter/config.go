package main

import (
	"crypto/tls"
	"encoding/json"
	"os"
)

type Config struct {
	// Maximum allowed time after test creation in which updates (like
	// client results) are accepted.
	MutableTestPeriodSecs int

	// Test cases that the client should execute.
	Subtests []SubtestSpec

	// Timeout for reading the initial Client Hello message.
	InitialReadTimeoutSecs int

	// Database connection configuration.
	DatabaseConnInfo string

	// Host and port to listen on for the reporter API and test endpoints.
	// The port will also be used in flash policy responses.
	ListenAddress string

	// Address to proxy connections to in case the host is not handled by
	// us. An empty value prevents proxying.
	OriginAddress string

	// Host and port to listen on for the Flash Socket Policy server. Flash
	// requires port 587 to answer requests. Leave the setting empty to
	// disable the additional service.
	FlashListenAddress string

	// Host name (suffix) for various purposes.
	HostReporter   string // Reporter API
	HostSuffixIPv4 string // IPv4 tests
	HostSuffixIPv6 string // IPv6 tests

	// Path prefix for the Reporter API.
	ReporterApiPrefix string

	// Local filesystem path to serve static files from. Leave empty to
	// avoid serving files.
	ReporterStaticFilesRoot string

	// Certificate file for the reporter service.
	ReporterCertificate string
	// Private key file for the reporter service.
	ReporterPrivateKey string

	// Certificate file for the dummy test service.
	DummyCertificate string
	// Private key file for the dummy test service.
	DummyPrivateKey string

	// SHA256 hash of the API key that grants access to privileged reporter
	// API endpoints. The API key MUST be cryptographically random. An empty
	// value prevents access to the privileged endpoint.
	ReporterApiKeyHash string
}

var defaultConfig = Config{
	MutableTestPeriodSecs: 15 * 60,

	Subtests: []SubtestSpec{
		{Number: 1, MaxTLSVersion: tls.VersionTLS12, IsIPv6: false},
		{Number: 2, MaxTLSVersion: tls.VersionTLS12, IsIPv6: true},
		{Number: 3, MaxTLSVersion: tls.VersionTLS13, IsIPv6: false},
		{Number: 4, MaxTLSVersion: tls.VersionTLS13, IsIPv6: true},
	},

	DatabaseConnInfo: "sslmode=disable",
	ListenAddress:    ":4433",

	OriginAddress:          "",
	InitialReadTimeoutSecs: 10,

	HostReporter:   "l.ls-l.info",
	HostSuffixIPv4: ".l4.ls-l.info",
	HostSuffixIPv6: ".l6.ls-l.info",

	ReporterApiPrefix:       "/api/v1",
	ReporterStaticFilesRoot: "../server/public",

	ReporterCertificate: "reporter.crt",
	ReporterPrivateKey:  "reporter.key",
	DummyCertificate:    "dummy.crt",
	DummyPrivateKey:     "dummy.key",
}

// (Partially) updates the configuration from the given file.
func (c *Config) Update(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	return dec.Decode(c)
}
