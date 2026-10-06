package disco

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"
)

func TestRoundTripAndSignature(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.UnixMilli(time.Now().UnixMilli())
	cases := []Message{
		{Type: Ping, Sender: [32]byte{1}, TxID: TxID{2}, Time: now},
		{Type: Pong, Sender: [32]byte{1}, TxID: TxID{3}, Time: now, PongTxID: TxID{2}, Observed: netip.MustParseAddrPort("203.0.113.10:7401")},
		{Type: Pong, Sender: [32]byte{1}, TxID: TxID{4}, Time: now, PongTxID: TxID{2}, Observed: netip.MustParseAddrPort("[2001:db8::1]:9")},
		{Type: CallMeMaybe, Sender: [32]byte{1}, TxID: TxID{5}, Time: now, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("10.1.0.2:7401"), netip.MustParseAddrPort("[2001:db8::2]:7401")}},
	}
	for _, m := range cases {
		encoded := Encode(m, private)
		if !IsMessage(encoded) {
			t.Fatal("magic missing")
		}
		got, err := Parse(encoded)
		if err != nil {
			t.Fatalf("type %d: %v", m.Type, err)
		}
		if got.Type != m.Type || got.Sender != m.Sender || got.TxID != m.TxID || !got.Time.Equal(m.Time) || got.PongTxID != m.PongTxID || got.Observed != m.Observed || len(got.Endpoints) != len(m.Endpoints) {
			t.Fatalf("round trip: %+v != %+v", got, m)
		}
		for i := range m.Endpoints {
			if got.Endpoints[i] != m.Endpoints[i] {
				t.Fatalf("endpoint %d: %v", i, got.Endpoints[i])
			}
		}
		if !got.Verify(public) || got.Verify(otherPublic) {
			t.Fatal("signature check")
		}
		// Any changed byte breaks the signature or the structure.
		for i := 8; i < len(encoded); i++ {
			tampered := append([]byte(nil), encoded...)
			tampered[i] ^= 1
			if parsed, err := Parse(tampered); err == nil && parsed.Verify(public) {
				t.Fatalf("type %d: byte %d tampered but accepted", m.Type, i)
			}
		}
	}
}

func TestFreshness(t *testing.T) {
	now := time.Now()
	for skew, fresh := range map[time.Duration]bool{0: true, 29 * time.Second: true, -29 * time.Second: true, 31 * time.Second: false, -31 * time.Second: false} {
		if (Message{Time: now.Add(-skew)}).Fresh(now) != fresh {
			t.Fatalf("skew %v", skew)
		}
	}
}

func TestRejectsMalformed(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	ping := Encode(Message{Type: Ping, Time: time.Now()}, private)
	cmm := Encode(Message{Type: CallMeMaybe, Time: time.Now(), Endpoints: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:1")}}, private)
	bad := [][]byte{
		nil,
		ping[:len(ping)-1],
		append([]byte{0x01}, ping[1:]...), // wrong magic
		append(append(append([]byte(nil), ping[:61]...), 0), ping[61:]...), // ping with a body
		append(append([]byte(nil), ping[:8]...), append([]byte{0x09}, ping[9:]...)...),
		append(append(append([]byte(nil), cmm[:61]...), 9), cmm[62:]...), // count above the limit
	}
	for i, b := range bad {
		if _, err := Parse(b); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}
