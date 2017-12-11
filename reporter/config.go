package main

import "crypto/tls"

type Config struct {
	Subtests []SubtestSpec // definition of test cases
}

var defaultConfig = Config{
	Subtests: []SubtestSpec{
		{Number: 1, MaxTLSVersion: tls.VersionTLS12, IsIPv6: false},
		{Number: 2, MaxTLSVersion: tls.VersionTLS12, IsIPv6: true},
		{Number: 3, MaxTLSVersion: tls.VersionTLS13, IsIPv6: false},
		{Number: 4, MaxTLSVersion: tls.VersionTLS13, IsIPv6: true},
	},
}
