package main

import "crypto/tls"

type Config struct {
	// Maximum allowed time after test creation in which updates (like
	// client results) are accepted.
	MutableTestPeriodSecs int

	// Test cases that the client should execute.
	Subtests []SubtestSpec
}

var defaultConfig = Config{
	MutableTestPeriodSecs: 15 * 60,

	Subtests: []SubtestSpec{
		{Number: 1, MaxTLSVersion: tls.VersionTLS12, IsIPv6: false},
		{Number: 2, MaxTLSVersion: tls.VersionTLS12, IsIPv6: true},
		{Number: 3, MaxTLSVersion: tls.VersionTLS13, IsIPv6: false},
		{Number: 4, MaxTLSVersion: tls.VersionTLS13, IsIPv6: true},
	},
}
