// +build ignore

// make a dummy certificate
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func MakeCertificate(certFilePath, keyFilePath string, template *x509.Certificate, overwrite bool) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate key: %s", err)
	}
	privDer, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("Failed to encode private key: %s", err)
	}

	pub := priv.Public()
	certDer, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}

	createFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !overwrite {
		createFlags |= os.O_EXCL
	}

	// Write key file first, then create (or append) certificate.
	keyFile, err := os.OpenFile(keyFilePath, createFlags, 0600)
	if err != nil {
		return fmt.Errorf("Failed to write key file: %s", err)
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDer})

	certFile := keyFile
	if certFilePath != keyFilePath {
		certFile, err = os.OpenFile(certFilePath, createFlags, 0666)
		if err != nil {
			return fmt.Errorf("Failed to write cert file: %s", err)
		}
		defer certFile.Close()
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDer})

	return nil
}

func MustRandomSerialNumber() *big.Int {
	// taken from tls/generate_cert.go
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %s", err)
	}
	return serialNumber
}

func NewServerCertificate() *x509.Certificate {
	notBefore := time.Now()
	return &x509.Certificate{
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(365 * 24 * time.Hour),
		SerialNumber:          MustRandomSerialNumber(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func MakeDummyCertificate(config *Config, overwrite bool) error {
	if config.DummyCertificate == "" || config.DummyPrivateKey == "" {
		return errors.New("DummyCertificate and DummyPrivateKey must be set")
	}

	template := NewServerCertificate()
	template.DNSNames = []string{
		"*" + config.HostSuffixIPv4,
		"*" + config.HostSuffixIPv6,
	}
	return MakeCertificate(config.DummyCertificate, config.DummyPrivateKey, template, overwrite)
}

func MakeReporterCertificate(config *Config, overwrite bool) error {
	if config.ReporterCertificate == "" || config.ReporterPrivateKey == "" {
		return errors.New("ReporterCertificate and ReporterPrivateKey must be set")
	}

	template := NewServerCertificate()
	template.DNSNames = []string{
		config.HostReporter,
	}
	return MakeCertificate(config.ReporterCertificate, config.ReporterPrivateKey, template, overwrite)
}

func main() {
	var configFile string
	var wantDummy, wantReporter, overwrite bool
	flag.StringVar(&configFile, "config", "", "Configuration file (JSON)")
	flag.BoolVar(&wantDummy, "create-dummy", true, "Whether to create the dummy test certificate")
	flag.BoolVar(&wantReporter, "create-reporter", false, "Whether to create the reporter service certificate")
	flag.BoolVar(&overwrite, "overwrite", false, "Whether to overwrite existing files")
	flag.Parse()

	config := &defaultConfig
	if configFile != "" {
		if err := config.Update(configFile); err != nil {
			log.Fatalf("Failed to load config: %s", err)
		}
	}

	if wantDummy {
		if err := MakeDummyCertificate(config, overwrite); err != nil {
			log.Fatalln(err)
		}
	}

	if wantReporter {
		if err := MakeReporterCertificate(config, overwrite); err != nil {
			log.Fatalln(err)
		}
	}
}
