package main

import (
	"crypto/tls"

	"golang.org/x/crypto/cryptobyte"
)

// TLS protocol constants
const (
	recordTypeHandshake uint8  = 22
	typeClientHello     uint8  = 1
	extensionServerName uint16 = 0
	sniTypeHostname     uint8  = 0
)

// parseClientHello tries to parse a TLS record and extract the SNI.
func parseClientHello(record []byte) string {
	input := cryptobyte.String(record)

	// parse record, but skip version
	var contentType uint8
	var fragment cryptobyte.String
	if !input.ReadUint8(&contentType) ||
		contentType != recordTypeHandshake ||
		!input.Skip(2) || !input.ReadUint16LengthPrefixed(&fragment) {
		return ""
	}

	// parse Handshake message
	var msgType uint8
	var clientHello cryptobyte.String
	if !fragment.ReadUint8(&msgType) || msgType != typeClientHello ||
		!fragment.ReadUint24LengthPrefixed(&clientHello) {
		return ""
	}

	// Parse Client Hello message (ignore random, SID, cipher suites,
	// compression methods, only preserve extensions).
	var tlsVersion uint16
	var ignore, exts cryptobyte.String
	if !clientHello.ReadUint16(&tlsVersion) ||
		!(tlsVersion >= tls.VersionTLS10 && tlsVersion <= tls.VersionTLS12) ||
		!clientHello.Skip(32) ||
		!clientHello.ReadUint8LengthPrefixed(&ignore) ||
		!clientHello.ReadUint16LengthPrefixed(&ignore) ||
		!clientHello.ReadUint8LengthPrefixed(&ignore) ||
		!clientHello.ReadUint16LengthPrefixed(&exts) {
		return ""
	}

	// Parse extensions
	for !exts.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&extType) ||
			!exts.ReadUint16LengthPrefixed(&extData) {
			return ""
		}
		if extType != extensionServerName {
			continue
		}

		var serverNameList cryptobyte.String
		if !extData.ReadUint16LengthPrefixed(&serverNameList) {
			return ""
		}
		for !serverNameList.Empty() {
			var nameType uint8
			if !serverNameList.ReadUint8(&nameType) {
				return ""
			}
			if nameType != sniTypeHostname {
				continue
			}

			var hostName cryptobyte.String
			if !serverNameList.ReadUint16LengthPrefixed(&hostName) {
				return ""
			}
			return string(hostName)
		}

		// extensions must be unique
		return ""
	}

	// server_name extension not found
	return ""
}
