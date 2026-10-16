package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/peerspan/peerspan/go/internal/tlsid"
)

func TestCertificateValidityAndIdentityPins(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "host"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cert, err := s.peerCertificate()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	public, err := tlsid.Key(leaf)
	if err != nil || keyID(public) != s.Identity().ID {
		t.Fatalf("certificate identity: %v", err)
	}
	leaf.NotAfter = time.Now().Add(-time.Second)
	if _, err := tlsid.Key(leaf); err == nil {
		t.Fatal("expired certificate accepted")
	}
	leaf.NotAfter = time.Now().Add(time.Hour)
	leaf.NotBefore = time.Now().Add(time.Hour)
	if _, err := tlsid.Key(leaf); err == nil {
		t.Fatal("future certificate accepted")
	}
	expected := Peer{ID: s.Identity().ID, PublicKey: s.Identity().PublicKey}
	config, err := s.PeerTLS(ctx, &expected)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{fresh}}); err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fresh.PublicKey = other.Public()
	if err = config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{fresh}}); err == nil {
		t.Fatal("incorrect identity pin accepted")
	}
}

func TestPinnedCertificateStillRequiresHandshakeProof(t *testing.T) {
	ctx := context.Background()
	receiver, err := Open(ctx, filepath.Join(t.TempDir(), "receiver"))
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := Open(ctx, filepath.Join(t.TempDir(), "sender"))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	_, err = receiver.AddPeer(ctx, Peer{ID: sender.Identity().ID, PublicKey: sender.Identity().PublicKey, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := receiver.PeerTLS(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := sender.PeerTLS(ctx, &Peer{ID: receiver.Identity().ID, PublicKey: receiver.Identity().PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	// Present the pinned sender's certificate but sign the handshake with a key
	// that does not belong to it. A trust callback alone must never authenticate it.
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.Certificates[0].PrivateKey = wrongPrivate
	serverWire, clientWire := net.Pipe()
	defer serverWire.Close()
	defer clientWire.Close()
	deadline := time.Now().Add(3 * time.Second)
	serverWire.SetDeadline(deadline)
	clientWire.SetDeadline(deadline)
	result := make(chan error, 1)
	go func() { result <- tls.Server(serverWire, serverConfig).Handshake() }()
	_ = tls.Client(clientWire, clientConfig).Handshake()
	if err := <-result; err == nil {
		t.Fatal("handshake accepted a certificate without proof of its private key")
	}
}
