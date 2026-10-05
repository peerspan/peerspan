// Package tlsid builds self-signed TLS 1.3 certificates that prove possession
// of an Ed25519 identity key. Trust comes from pinned keys, not from a CA.
package tlsid

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"time"
)

const (
	Lifetime = 30 * 24 * time.Hour
	Renewal  = 15 * 24 * time.Hour
)

// Certificate returns a certificate for key, valid for Lifetime from now.
func Certificate(key ed25519.PrivateKey, name string, now time.Time) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(Lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Cache serves a listener's certificate, replacing it with one for the same
// key once less than Renewal of validity remains.
type Cache struct {
	Key  ed25519.PrivateKey
	Name string
	Now  func() time.Time
	mu   sync.Mutex
	cert *tls.Certificate
}

func (c *Cache) Get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	if c.cert == nil || !now.Add(Renewal).Before(c.cert.Leaf.NotAfter) {
		cert, err := Certificate(c.Key, c.Name, now)
		if err != nil {
			return nil, err
		}
		c.cert = &cert
	}
	return c.cert, nil
}

// Key returns the Ed25519 key of a currently valid certificate. The TLS
// handshake has already verified the peer's signature with this key.
func Key(cert *x509.Certificate) (ed25519.PublicKey, error) {
	public, ok := cert.PublicKey.(ed25519.PublicKey)
	now := time.Now()
	if !ok || len(public) != ed25519.PublicKeySize || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || len(cert.UnhandledCriticalExtensions) > 0 {
		return nil, errors.New("invalid peer certificate")
	}
	return public, nil
}

// Config returns TLS 1.3 settings without session resumption, so that every
// connection proves identity. Callers add certificates and VerifyConnection.
func Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
}

// PeerKey returns the single valid certificate key of an established connection.
func PeerKey(state tls.ConnectionState) (ed25519.PublicKey, error) {
	if len(state.PeerCertificates) != 1 {
		return nil, errors.New("one peer certificate required")
	}
	return Key(state.PeerCertificates[0])
}
