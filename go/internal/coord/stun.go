package coord

import (
	"errors"
	"net"
	"net/netip"

	"github.com/Cerebral-Systems/capsule/go/internal/stun"
)

// listenSTUN binds UDP on the TLS listener's IP and port, where hosts learn
// their public UDP mapping.
func listenSTUN(addr net.Addr) (*net.UDPConn, error) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return nil, errors.New("coordinator listener is not TCP")
	}
	return net.ListenUDP("udp", &net.UDPAddr{IP: tcp.IP, Port: tcp.Port, Zone: tcp.Zone})
}

// serveSTUN answers Binding requests with the observed source address and
// ignores every other datagram. Answers are unauthenticated: a wrong mapping
// can only cause a failed path attempt, since peer TLS pins still apply.
func serveSTUN(conn *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		tx, ok := stun.ParseRequest(buf[:n])
		if !ok {
			continue
		}
		observed := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		_, _ = conn.WriteToUDPAddrPort(stun.Response(tx, observed), from)
	}
}
