// Certificate and private key loader.
package main

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type CertificateLoader struct {
	certificateFile string
	privateKeyFile  string
	certificate     *tls.Certificate
	lock            sync.RWMutex

	// Used for checking whether the certificate needs to be reloaded.
	uptodate bool
	checking int32
	mtime    time.Time
}

func NewCertificateLoader(certificateFile, privateKeyFile string) *CertificateLoader {
	return &CertificateLoader{
		certificateFile: certificateFile,
		privateKeyFile:  privateKeyFile,
	}
}

// Loads the configured certificate from file and returns the (cached) result.
// If the new certificate failed to load, the previous cached result is returned
// with an error message.
func (cl *CertificateLoader) Load() (*tls.Certificate, error) {
	cert, uptodate := cl.loadFromCache()
	if uptodate {
		return cert, nil
	}

	// out of date, try to update the cert or keep old cert (if any).
	cl.lock.Lock()
	defer cl.lock.Unlock()
	newCert, err := tls.LoadX509KeyPair(cl.certificateFile, cl.privateKeyFile)
	if err == nil {
		log.Printf("(Re)loaded certificate from %s", cl.certificateFile)
		cl.certificate = &newCert
		cl.uptodate = true
	}
	return cl.certificate, err
}

func (cl *CertificateLoader) loadFromCache() (*tls.Certificate, bool) {
	cl.lock.RLock()
	defer cl.lock.RUnlock()
	uptodate := cl.uptodate
	if uptodate {
		uptodate = cl.checkStaleCache()
	}
	return cl.certificate, uptodate
}

// under read lock, returns true if the certificate does not need a reload.
func (cl *CertificateLoader) checkStaleCache() bool {
	if !atomic.CompareAndSwapInt32(&cl.checking, 0, 1) {
		// Something else is already checking whether cache is outdated.
		return true
	}
	defer atomic.StoreInt32(&cl.checking, 0)

	finfo, err := os.Stat(cl.certificateFile)
	if err != nil {
		// Do not mark as out-of-date since loading would likely fail.
		return true
	}
	if finfo.ModTime() == cl.mtime {
		return true
	}

	cl.mtime = finfo.ModTime()
	return false
}
