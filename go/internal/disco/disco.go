// Package disco encodes the signed path discovery messages that relay-capable
// peers exchange to find and keep a direct UDP path.
package disco

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Magic starts every path discovery datagram: "\0capdisc".
var Magic = [8]byte{0x00, 'c', 'a', 'p', 'd', 'i', 's', 'c'}

// Message types.
const (
	Ping        byte = 0x01
	Pong        byte = 0x02
	CallMeMaybe byte = 0x03
)

// MaxEndpoints bounds a call-me-maybe's endpoint list.
const MaxEndpoints = 8

// Freshness and replay bounds from the messaging contract.
const (
	MaxSkew      = 30 * time.Second
	ReplayWindow = 60 * time.Second
)

const (
	headerLen = 8 + 1 + 32 + 12 + 8
	sigLen    = ed25519.SignatureSize
)

var errMalformed = errors.New("malformed path discovery message")

// TxID identifies a ping and the pong that answers it.
type TxID [12]byte

// Message is a parsed message. Signed is every byte the signature covers.
type Message struct {
	Type   byte
	Sender [32]byte
	TxID   TxID
	Time   time.Time
	// Pong fields.
	PongTxID TxID
	Observed netip.AddrPort
	// Call-me-maybe field.
	Endpoints []netip.AddrPort

	signed    []byte
	signature []byte
}

// IsMessage reports whether a datagram starts with the discovery magic.
func IsMessage(b []byte) bool {
	return len(b) >= len(Magic) && [8]byte(b[:8]) == Magic
}

// AppendEndpoint encodes a family byte, the address, and a big-endian port.
// IPv4-mapped IPv6 addresses are written as IPv4.
func AppendEndpoint(b []byte, e netip.AddrPort) []byte {
	addr := e.Addr().Unmap()
	if addr.Is4() {
		b = append(b, 4)
	} else {
		b = append(b, 6)
	}
	b = append(b, addr.AsSlice()...)
	return binary.BigEndian.AppendUint16(b, e.Port())
}

func readEndpoint(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, nil, errMalformed
	}
	size := map[byte]int{4: 4, 6: 16}[b[0]]
	if size == 0 || len(b) < 1+size+2 {
		return netip.AddrPort{}, nil, errMalformed
	}
	addr, _ := netip.AddrFromSlice(b[1 : 1+size])
	port := binary.BigEndian.Uint16(b[1+size : 3+size])
	return netip.AddrPortFrom(addr, port), b[3+size:], nil
}

// Encode builds and signs a message. Body fields are taken from m by type.
func Encode(m Message, key ed25519.PrivateKey) []byte {
	b := append([]byte(nil), Magic[:]...)
	b = append(b, m.Type)
	b = append(b, m.Sender[:]...)
	b = append(b, m.TxID[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(m.Time.UnixMilli()))
	switch m.Type {
	case Pong:
		b = append(b, m.PongTxID[:]...)
		observed := m.Observed
		if !observed.IsValid() {
			observed = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
		}
		b = AppendEndpoint(b, observed)
	case CallMeMaybe:
		endpoints := m.Endpoints
		if len(endpoints) > MaxEndpoints {
			endpoints = endpoints[:MaxEndpoints]
		}
		b = append(b, byte(len(endpoints)))
		for _, e := range endpoints {
			b = AppendEndpoint(b, e)
		}
	}
	return append(b, ed25519.Sign(key, b)...)
}

// Parse checks a message's structure. The caller must still check its sender,
// signature (Verify), freshness (Fresh), and replay.
func Parse(b []byte) (Message, error) {
	var m Message
	if !IsMessage(b) || len(b) < headerLen+sigLen {
		return m, errMalformed
	}
	body := b[headerLen : len(b)-sigLen]
	m.Type = b[8]
	copy(m.Sender[:], b[9:41])
	copy(m.TxID[:], b[41:53])
	m.Time = time.UnixMilli(int64(binary.BigEndian.Uint64(b[53:61])))
	m.signed, m.signature = b[:len(b)-sigLen], b[len(b)-sigLen:]
	var err error
	switch m.Type {
	case Ping:
		if len(body) != 0 {
			return m, errMalformed
		}
	case Pong:
		if len(body) < 12 {
			return m, errMalformed
		}
		copy(m.PongTxID[:], body[:12])
		if m.Observed, body, err = readEndpoint(body[12:]); err != nil || len(body) != 0 {
			return m, errMalformed
		}
	case CallMeMaybe:
		if len(body) < 1 || int(body[0]) > MaxEndpoints {
			return m, errMalformed
		}
		count := int(body[0])
		body = body[1:]
		for range count {
			var e netip.AddrPort
			if e, body, err = readEndpoint(body); err != nil {
				return m, err
			}
			m.Endpoints = append(m.Endpoints, e)
		}
		if len(body) != 0 {
			return m, errMalformed
		}
	default:
		return m, errMalformed
	}
	return m, nil
}

// Verify checks the signature with the sender's pinned host key.
func (m Message) Verify(public ed25519.PublicKey) bool {
	return len(public) == ed25519.PublicKeySize && ed25519.Verify(public, m.signed, m.signature)
}

// Fresh reports whether the message time is within MaxSkew of now.
func (m Message) Fresh(now time.Time) bool {
	skew := now.Sub(m.Time)
	return skew <= MaxSkew && skew >= -MaxSkew
}
