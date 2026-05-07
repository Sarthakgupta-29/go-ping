package main

import (
	"encoding/binary"
	"errors"
)

// ICMP message types relevant to ping.
const (
	ICMPTypeEchoReply   uint8 = 0
	ICMPTypeEchoRequest uint8 = 8
)

var errTruncated = errors.New("packet too short")

// ICMP represents an ICMP echo request or reply.
type ICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Data     []byte
}

// Marshal serializes the ICMP message and computes its checksum.
func (m *ICMP) Marshal() []byte {
	b := make([]byte, 8+len(m.Data))
	b[0] = m.Type
	b[1] = m.Code
	binary.BigEndian.PutUint16(b[2:], 0) // zero while computing checksum
	binary.BigEndian.PutUint16(b[4:], m.ID)
	binary.BigEndian.PutUint16(b[6:], m.Seq)
	copy(b[8:], m.Data)

	cs := checksum(b)
	binary.BigEndian.PutUint16(b[2:], cs)
	return b
}

// UnmarshalICMP parses a raw byte slice into an ICMP struct.
// Used when reading a reply off the wire.
func UnmarshalICMP(b []byte) (*ICMP, error) {
	if len(b) < 8 {
		return nil, errTruncated
	}
	m := &ICMP{
		Type:     b[0],
		Code:     b[1],
		Checksum: binary.BigEndian.Uint16(b[2:]),
		ID:       binary.BigEndian.Uint16(b[4:]),
		Seq:      binary.BigEndian.Uint16(b[6:]),
	}
	if len(b) > 8 {
		m.Data = make([]byte, len(b)-8)
		copy(m.Data, b[8:])
	}
	return m, nil
}

// checksum implements the Internet checksum (RFC 1071).
func checksum(data []byte) uint16 {
	var sum uint32
	i := 0
	for ; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	// Odd byte: treat as the high-order byte of a zero-padded word.
	if i < len(data) {
		sum += uint32(data[i]) << 8
	}
	// Fold carries back into 16 bits.
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

