// Package stun implements the STUN Binding exchange (RFC 8489) used to learn a
// host's public UDP mapping: requests carry no attributes, and responses carry
// only XOR-MAPPED-ADDRESS.
package stun

import (
	"encoding/binary"
	"net/netip"
)

// Cookie is the STUN magic cookie at bytes 4–7 of every message.
const Cookie = 0x2112A442

const (
	headerLen       = 20
	bindingRequest  = 0x0001
	bindingSuccess  = 0x0101
	xorMappedAddr   = 0x0020
	familyIPv4      = 0x01
	familyIPv6      = 0x02
	maxMessageBytes = 548
)

// TxID is a STUN transaction ID.
type TxID [12]byte

// IsMessage reports whether a datagram is shaped like STUN: its first two bits
// are zero and bytes 4–7 hold the magic cookie.
func IsMessage(b []byte) bool {
	return len(b) >= headerLen && b[0]&0xC0 == 0 && binary.BigEndian.Uint32(b[4:8]) == Cookie
}

func header(kind uint16, length int, tx TxID) []byte {
	b := make([]byte, headerLen, headerLen+length)
	binary.BigEndian.PutUint16(b[0:2], kind)
	binary.BigEndian.PutUint16(b[2:4], uint16(length))
	binary.BigEndian.PutUint32(b[4:8], Cookie)
	copy(b[8:20], tx[:])
	return b
}

// parse checks the header and returns the message type, transaction ID, and
// attribute bytes.
func parse(b []byte) (uint16, TxID, []byte, bool) {
	var tx TxID
	if !IsMessage(b) || len(b) > maxMessageBytes {
		return 0, tx, nil, false
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length%4 != 0 || headerLen+length != len(b) {
		return 0, tx, nil, false
	}
	copy(tx[:], b[8:20])
	return binary.BigEndian.Uint16(b[0:2]), tx, b[headerLen:], true
}

// Request encodes a Binding request with no attributes.
func Request(tx TxID) []byte { return header(bindingRequest, 0, tx) }

// ParseRequest accepts a Binding request and ignores any attributes it carries.
func ParseRequest(b []byte) (TxID, bool) {
	kind, tx, _, ok := parse(b)
	return tx, ok && kind == bindingRequest
}

// Response encodes a Binding success response carrying the observed address.
func Response(tx TxID, observed netip.AddrPort) []byte {
	addr := observed.Addr().Unmap()
	value := []byte{0, familyIPv4}
	if addr.Is6() {
		value[1] = familyIPv6
	}
	value = binary.BigEndian.AppendUint16(value, observed.Port()^uint16(Cookie>>16))
	mask := make([]byte, 4, 16)
	binary.BigEndian.PutUint32(mask, Cookie)
	raw := addr.AsSlice()
	if addr.Is6() {
		mask = append(mask, tx[:]...)
	}
	for i := range raw {
		value = append(value, raw[i]^mask[i])
	}
	attribute := binary.BigEndian.AppendUint16(nil, xorMappedAddr)
	attribute = binary.BigEndian.AppendUint16(attribute, uint16(len(value)))
	attribute = append(attribute, value...)
	return append(header(bindingSuccess, len(attribute), tx), attribute...)
}

// ParseResponse returns the transaction ID and XOR-MAPPED-ADDRESS of a Binding
// success response.
func ParseResponse(b []byte) (TxID, netip.AddrPort, bool) {
	kind, tx, attributes, ok := parse(b)
	if !ok || kind != bindingSuccess {
		return tx, netip.AddrPort{}, false
	}
	for len(attributes) >= 4 {
		kind := binary.BigEndian.Uint16(attributes[0:2])
		length := int(binary.BigEndian.Uint16(attributes[2:4]))
		padded := (length + 3) &^ 3
		if 4+padded > len(attributes) {
			break
		}
		value := attributes[4 : 4+length]
		attributes = attributes[4+padded:]
		if kind != xorMappedAddr || len(value) < 4 {
			continue
		}
		port := binary.BigEndian.Uint16(value[2:4]) ^ uint16(Cookie>>16)
		mask := binary.BigEndian.AppendUint32(nil, Cookie)
		var raw []byte
		switch {
		case value[1] == familyIPv4 && len(value) == 8:
			raw = value[4:8]
		case value[1] == familyIPv6 && len(value) == 20:
			raw = value[4:20]
			mask = append(mask, tx[:]...)
		default:
			continue
		}
		ip := make([]byte, len(raw))
		for i := range raw {
			ip[i] = raw[i] ^ mask[i]
		}
		addr, _ := netip.AddrFromSlice(ip)
		return tx, netip.AddrPortFrom(addr.Unmap(), port), true
	}
	return tx, netip.AddrPort{}, false
}
