package tlsid

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestListenerCertificateRenewsBeforeExpiry(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cache := &Cache{Key: key, Name: "host_test", Now: func() time.Time { return now }}
	first, err := cache.Get()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(Lifetime - Renewal - time.Minute)
	if reused, err := cache.Get(); err != nil || reused != first {
		t.Fatalf("certificate outside renewal window was replaced: %v", err)
	}
	now = now.Add(2 * time.Minute)
	renewed, err := cache.Get()
	if err != nil || renewed == first {
		t.Fatalf("certificate inside renewal window was not replaced: %v", err)
	}
	if !renewed.Leaf.NotAfter.After(first.Leaf.NotAfter) || renewed.Leaf.NotAfter.Sub(now) < Lifetime-time.Second {
		t.Fatal("renewed certificate lacks fresh validity")
	}
	public, ok := renewed.Leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !public.Equal(key.Public()) {
		t.Fatal("renewal changed host identity")
	}
}
