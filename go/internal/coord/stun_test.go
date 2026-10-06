package coord

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/stun"
)

// The coordinator answers STUN Binding requests on its listener's IP and port
// with the observed source, and ignores other datagrams.
func TestSTUNBindingOnListenerPort(t *testing.T) {
	h := startRelay(t, nil)
	server := netip.MustParseAddrPort(h.addr)
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	local := netip.MustParseAddrPort(client.LocalAddr().String())
	buf := make([]byte, 1500)
	// Not STUN, or STUN but not a Binding request: no answer.
	for _, ignored := range [][]byte{[]byte("hello"), {0x40, 1, 2, 3}, stun.Response(stun.TxID{7}, local)} {
		if _, err = client.WriteToUDPAddrPort(ignored, server); err != nil {
			t.Fatal(err)
		}
	}
	// Serve binds UDP asynchronously; resend like a real client would.
	tx := stun.TxID{1, 2, 3}
	var n int
	var from netip.AddrPort
	for attempt := 0; ; attempt++ {
		if _, err = client.WriteToUDPAddrPort(stun.Request(tx), server); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if n, from, err = client.ReadFromUDPAddrPort(buf); err == nil {
			break
		}
		if attempt == 30 {
			t.Fatal(err)
		}
	}
	gotTx, observed, ok := stun.ParseResponse(buf[:n])
	if !ok || gotTx != tx || observed != local || from.Port() != server.Port() {
		t.Fatalf("response %v %v %v from %v", ok, gotTx, observed, from)
	}
}
