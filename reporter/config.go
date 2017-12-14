package main

import (
	"crypto/tls"
)

type Config struct {
	// Maximum allowed time after test creation in which updates (like
	// client results) are accepted.
	MutableTestPeriodSecs int

	// Test cases that the client should execute.
	Subtests []SubtestSpec

	// Timeout for reading the initial Client Hello message, and the timeout
	// for processing requests.
	SessionTimeoutSecs int

	// Database connection configuration.
	DatabaseConnInfo string

	// Host and port to listen on
	ListenAddress string

	// Address to proxy connections to in case the host is not handled by
	// us. An empty value prevents proxying.
	OriginAddress string

	// Host name (suffix) for various purposes.
	HostReporter   string // Reporter API
	HostSuffixIPv4 string // IPv4 tests
	HostSuffixIPv6 string // IPv6 tests

	// Path prefix for the Reporter API.
	ReporterApiPrefix string

	// Local filesystem path to serve static files from. Leave empty to
	// avoid serving files.
	ReporterStaticFilesRoot string
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

	OriginAddress:      "",
	SessionTimeoutSecs: 60,

	HostReporter:   "l.ls-l.info",
	HostSuffixIPv4: ".l4.ls-l.info",
	HostSuffixIPv6: ".l6.ls-l.info",

	ReporterApiPrefix:       "/api/v1",
	ReporterStaticFilesRoot: "../server/public",
}
