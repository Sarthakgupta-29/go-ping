package ipv4

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
)

var errTruncated = errors.New("header too short")

// Header represents a minimal 20-byte IPv4 header (no options).
type Header struct {
	VerIHL         uint8  // Version(4) << 4 | IHL(4)
	DSCP           uint8  // DSCP(6) | ECN(2)
	TotalLength    uint16 // Header + payload length
	Identification uint16
	FlagsFragOff   uint16 // Flags(3) << 13 | FragmentOffset(13)
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcAddr        [4]byte
	DstAddr        [4]byte
}

// New builds a ready-to-use IPv4 header for a given source, destination,
// protocol, and total packet length (header + payload).
func New(src, dst net.IP, protocol uint8, totalLength uint16) (*Header, error) {
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		return nil, errors.New("only IPv4 addresses are supported")
	}

	h := &Header{
		VerIHL:         (4 << 4) | 5, // version 4, IHL = 5 (20 bytes, no options)
		DSCP:           0,
		TotalLength:    totalLength,
		Identification: uint16(rand.Uint32()), // #nosec G404 — not cryptographic
		FlagsFragOff:   0x4000,                // Don't Fragment bit set
		TTL:            64,
		Protocol:       protocol,
		HeaderChecksum: 0,
	}
	copy(h.SrcAddr[:], src4)
	copy(h.DstAddr[:], dst4)
	return h, nil
}

// Marshal serializes the header to 20 bytes and fills in the checksum.
func (h *Header) Marshal() []byte {
	b := make([]byte, 20)
	b[0] = h.VerIHL
	b[1] = h.DSCP
	binary.BigEndian.PutUint16(b[2:], h.TotalLength)
	binary.BigEndian.PutUint16(b[4:], h.Identification)
	binary.BigEndian.PutUint16(b[6:], h.FlagsFragOff)
	b[8] = h.TTL
	b[9] = h.Protocol
	binary.BigEndian.PutUint16(b[10:], 0) // checksum = 0 during calculation
	copy(b[12:16], h.SrcAddr[:])
	copy(b[16:20], h.DstAddr[:])

	cs := checksum(b)
	binary.BigEndian.PutUint16(b[10:], cs)
	return b
}

// Unmarshal parses a 20-byte (minimum) slice into a Header.
func Unmarshal(b []byte) (*Header, error) {
	if len(b) < 20 {
		return nil, errTruncated
	}
	h := &Header{
		VerIHL:         b[0],
		DSCP:           b[1],
		TotalLength:    binary.BigEndian.Uint16(b[2:]),
		Identification: binary.BigEndian.Uint16(b[4:]),
		FlagsFragOff:   binary.BigEndian.Uint16(b[6:]),
		TTL:            b[8],
		Protocol:       b[9],
		HeaderChecksum: binary.BigEndian.Uint16(b[10:]),
	}
	copy(h.SrcAddr[:], b[12:16])
	copy(h.DstAddr[:], b[16:20])
	return h, nil
}

// SrcIP returns the source address as a net.IP.
func (h *Header) SrcIP() net.IP { return net.IP(h.SrcAddr[:]) }

// DstIP returns the destination address as a net.IP.
func (h *Header) DstIP() net.IP { return net.IP(h.DstAddr[:]) }

// checksum is the RFC 1071 Internet checksum.
func checksum(data []byte) uint16 {
	var sum uint32
	i := 0
	for ; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if i < len(data) {
		sum += uint32(data[i]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

