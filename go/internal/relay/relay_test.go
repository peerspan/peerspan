package relay

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestFramesRoundTripAndRejectInvalid(t *testing.T) {
	id, err := ParseHostID("host_" + strings.Repeat("ab", 32))
	if err != nil || id.String() != "host_"+strings.Repeat("ab", 32) {
		t.Fatal(id, err)
	}
	for _, bad := range []string{"host_" + strings.Repeat("AB", 32), "host_ab", "peer_" + strings.Repeat("ab", 32)} {
		if _, err := ParseHostID(bad); err == nil {
			t.Fatal(bad)
		}
	}
	var buf bytes.Buffer
	if err := Write(&buf, FrameSend, id[:], []byte("datagram")); err != nil {
		t.Fatal(err)
	}
	kind, peer, data, err := Read(bufio.NewReader(&buf), true)
	if err != nil || kind != FrameSend || peer != id || string(data) != "datagram" {
		t.Fatal(kind, peer, data, err)
	}
	if err := Write(&buf, FrameSend, id[:], make([]byte, MaxDatagram+1)); err == nil {
		t.Fatal("oversized datagram encoded")
	}
	cases := map[string]struct {
		frame    []byte
		fromHost bool
	}{
		"receive from host":     {append([]byte{FrameReceive, 0, 33}, make([]byte, 33)...), true},
		"send from relay":       {append([]byte{FrameSend, 0, 33}, make([]byte, 33)...), false},
		"unknown type":          {[]byte{0x09, 0, 0}, true},
		"empty datagram":        {append([]byte{FrameSend, 0, 32}, make([]byte, 32)...), true},
		"oversized length":      {[]byte{FrameSend, 0x06, 0x00}, true},
		"truncated":             {append([]byte{FrameSend, 0, 40}, make([]byte, 10)...), true},
		"ping with payload":     {[]byte{FramePing, 0, 1, 0}, true},
		"short unreachable":     {append([]byte{FrameUnreachable, 0, 31}, make([]byte, 31)...), false},
		"unreachable from host": {append([]byte{FrameUnreachable, 0, 32}, make([]byte, 32)...), true},
	}
	for name, c := range cases {
		if _, _, _, err := Read(bufio.NewReader(bytes.NewReader(c.frame)), c.fromHost); err == nil {
			t.Fatal(name)
		}
	}
	buf.Reset()
	_ = Write(&buf, FramePing)
	if kind, _, _, err := Read(bufio.NewReader(&buf), false); err != nil || kind != FramePing {
		t.Fatal(kind, err)
	}
}
