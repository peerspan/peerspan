package stun

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestBindingRoundTrip(t *testing.T) {
	tx := TxID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	request := Request(tx)
	if !IsMessage(request) || len(request) != 20 {
		t.Fatalf("request %x", request)
	}
	if got, ok := ParseRequest(request); !ok || got != tx {
		t.Fatal("request did not parse")
	}
	for _, observed := range []string{"203.0.113.10:41234", "[2001:db8::7]:7401"} {
		addr := netip.MustParseAddrPort(observed)
		response := Response(tx, addr)
		gotTx, got, ok := ParseResponse(response)
		if !ok || gotTx != tx || got != addr {
			t.Fatalf("%s: %v %v %v", observed, ok, gotTx, got)
		}
		if _, ok := ParseRequest(response); ok {
			t.Fatal("response parsed as a request")
		}
	}
}

// RFC 5769 section 2.2 gives an IPv4 Binding response; its XOR-MAPPED-ADDRESS
// must decode to 192.0.2.1:32853 with our parser even with other attributes.
func TestRFC5769IPv4Response(t *testing.T) {
	raw, _ := hex.DecodeString("0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643000800146e7e4a8f9b88f9f5b27e8d2dea0c2fa548f6ab6b80280004c07d4c96")
	tx, addr, ok := ParseResponse(raw)
	if !ok || addr != netip.MustParseAddrPort("192.0.2.1:32853") || !bytes.Equal(tx[:], raw[8:20]) {
		t.Fatalf("%v %v", ok, addr)
	}
}

func TestRejectsMalformedMessages(t *testing.T) {
	tx := TxID{9}
	good := Request(tx)
	bad := [][]byte{
		nil,
		good[:19],
		append(append([]byte(nil), good...), 0, 0, 0, 0),      // length field disagrees
		append([]byte{0x40}, good[1:]...),                     // QUIC-shaped first byte
		append(append([]byte(nil), good[:4]...), good[8:]...), // missing cookie
	}
	for i, b := range bad {
		if _, ok := ParseRequest(b); ok {
			t.Fatalf("case %d accepted", i)
		}
	}
	if _, _, ok := ParseResponse(Request(tx)); ok {
		t.Fatal("request parsed as a response")
	}
}
