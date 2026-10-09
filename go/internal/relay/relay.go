// Package relay defines the frames that carry already-encrypted peer QUIC
// datagrams between hosts and the capsule-coord relay. A relay never sees
// plaintext: the peer TLS connection runs end to end inside the datagrams.
package relay

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ALPN selects the relay protocol on the coordinator's TLS listener. Version
// 2 adds the changed frame; hosts offer it first and coordinators prefer it.
const (
	ALPN   = "capsule-relay/1"
	ALPNv2 = "capsule-relay/2"
)

const (
	FrameSend        byte = 0x01
	FrameReceive     byte = 0x02
	FrameUnreachable byte = 0x03
	FramePing        byte = 0x04
	// FrameChanged (version 2, relay to host) carries a network ID whose map
	// or stored statements changed.
	FrameChanged byte = 0x05
)

const (
	// HostIDSize is the length of the raw SHA-256 digest a host ID spells in hex.
	HostIDSize = 32
	// MaxDatagram bounds one forwarded QUIC datagram.
	MaxDatagram = 1500
	maxPayload  = HostIDSize + MaxDatagram
)

// HostID is the raw form of a "host_" + hex host ID.
type HostID [HostIDSize]byte

// ParseHostID decodes a "host_" + 64 lowercase hex host ID.
func ParseHostID(id string) (HostID, error) {
	var h HostID
	value, ok := strings.CutPrefix(id, "host_")
	if !ok || len(value) != 2*HostIDSize || strings.ToLower(value) != value {
		return h, errors.New("invalid host ID")
	}
	if _, err := hex.Decode(h[:], []byte(value)); err != nil {
		return h, errors.New("invalid host ID")
	}
	return h, nil
}

func (h HostID) String() string { return "host_" + hex.EncodeToString(h[:]) }

// Write encodes one frame: type, 2-byte big-endian payload length, payload.
func Write(w io.Writer, kind byte, parts ...[]byte) error {
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	if size > maxPayload {
		return errors.New("relay frame too large")
	}
	frame := make([]byte, 3, 3+size)
	frame[0], frame[1], frame[2] = kind, byte(size>>8), byte(size)
	for _, p := range parts {
		frame = append(frame, p...)
	}
	_, err := w.Write(frame)
	return err
}

// Read decodes one frame. fromHost selects which frame types are valid: a host
// sends send and ping frames; a relay sends receive, unreachable, ping, and
// (version 2) changed, whose network ID is returned as the datagram.
// Any invalid frame is an error, and the caller closes the connection.
func Read(r *bufio.Reader, fromHost bool) (kind byte, peer HostID, datagram []byte, err error) {
	var header [3]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return 0, peer, nil, err
	}
	kind, size := header[0], int(header[1])<<8|int(header[2])
	if size > maxPayload {
		return 0, peer, nil, fmt.Errorf("relay frame of %d bytes is too large", size)
	}
	payload := make([]byte, size)
	if _, err = io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, peer, nil, err
	}
	switch {
	case kind == FramePing:
		if size != 0 {
			return 0, peer, nil, errors.New("relay ping carries a payload")
		}
		return kind, peer, nil, nil
	case kind == FrameSend && fromHost, kind == FrameReceive && !fromHost:
		if size < HostIDSize+1 {
			return 0, peer, nil, errors.New("relay datagram frame is truncated")
		}
		copy(peer[:], payload)
		return kind, peer, payload[HostIDSize:], nil
	case kind == FrameChanged && !fromHost:
		if size == 0 {
			return 0, peer, nil, errors.New("relay changed frame has no network ID")
		}
		return kind, peer, payload, nil
	case kind == FrameUnreachable && !fromHost:
		if size != HostIDSize {
			return 0, peer, nil, errors.New("relay unreachable frame has the wrong size")
		}
		copy(peer[:], payload)
		return kind, peer, nil, nil
	}
	return 0, peer, nil, fmt.Errorf("unexpected relay frame type 0x%02x", kind)
}
