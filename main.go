package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"ping/ipv4"

	"github.com/architmishra-15/go-tables"
)

const (
	ProtocolICMP = 1
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <host>\n", os.Args[0])
		os.Exit(1)
	}

	host := os.Args[1]
	if err := ping(host); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func ping(host string) error {
	// Resolve the target host to an IP address (we need DNS, so keep this one net call)
	// Alternative: you could implement DNS resolution yourself using UDP port 53
	dstIP, err := resolve(host)
	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", host, err)
	}

	// Print beautiful header
	printPingHeader(host, dstIP)

	// Open a raw socket using syscall directly
	// AF_INET = 2, SOCK_RAW = 3, IPPROTO_ICMP = 1
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("failed to open raw socket (are you root?): %w", err)
	}
	defer syscall.Close(fd)

	// We don't need to bind since we're sending to a specific destination
	// The kernel will choose our source IP automatically


	// Ping parameters
	const (
		count       = 4
		payloadSize = 56
		timeout     = 2 * time.Second
	)

	// Unique identifier for this ping session (use PID)
	id := uint16(os.Getpid() & 0xFFFF)

	stats := &pingStats{}
	results := make([]pingResult, 0, count)

	for seq := uint16(0); seq < count; seq++ {
		if err := sendEchoRequest(fd, dstIP, id, seq, payloadSize); err != nil {
			fmt.Printf("Send failed: %v\n", err)
			continue
		}

		start := time.Now()
		reply, srcIP, rtt, err := receiveEchoReply(fd, id, seq, timeout)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ETIMEDOUT) {
				fmt.Printf("Request timeout for icmp_seq=%d\n", seq)
				stats.recordLoss()
				results = append(results, pingResult{
					seq:     seq,
					timeout: true,
				})
			} else {
				fmt.Printf("Receive error: %v\n", err)
				stats.recordLoss()
				results = append(results, pingResult{
					seq:   seq,
					error: err.Error(),
				})
			}
			continue
		}

		stats.recordSuccess(rtt)
		results = append(results, pingResult{
			seq:   seq,
			bytes: len(reply.Data) + 8, // ICMP header + data
			from:  ipToString(srcIP),
			ttl:   64,
			rtt:   rtt,
		})

		fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
			len(reply.Data)+8, ipToString(srcIP), reply.Seq, 64, rtt.Seconds()*1000)

		// Wait before sending next packet (roughly 1 second interval)
		if seq < count-1 {
			time.Sleep(time.Second - time.Since(start))
		}
	}

	printPingResults(host, stats, results)
	return nil
}

// pingResult stores the result of a single ping
type pingResult struct {
	seq     uint16
	bytes   int
	from    string
	ttl     uint8
	rtt     time.Duration
	timeout bool
	error   string
}

func printPingHeader(host string, ip [4]byte) {
	fmt.Println()
	
	// Create header table
	headers := []string{"PING UTILITY"}
	t := tables.NewFromStrings(headers...)
	
	t.AddRow("Target: " + host)
	t.AddRow("IP: " + ipToString(ip))
	
	t.Print()
	fmt.Println()
}

func printPingResults(host string, stats *pingStats, results []pingResult) {
	fmt.Println()
	
	// Create results table
	headers := []string{"Seq", "Bytes", "From", "TTL", "Time (ms)", "Status"}
	t := tables.NewFromStrings(headers...)

	for _, r := range results {
		if r.timeout {
			t.AddRow(
				fmt.Sprintf("%d", r.seq),
				"-",
				"-",
				"-",
				"-",
				"Timeout",
			)
		} else if r.error != "" {
			t.AddRow(
				fmt.Sprintf("%d", r.seq),
				"-",
				"-",
				"-",
				"-",
				"Error",
			)
		} else {
			t.AddRow(
				fmt.Sprintf("%d", r.seq),
				fmt.Sprintf("%d", r.bytes),
				r.from,
				fmt.Sprintf("%d", r.ttl),
				fmt.Sprintf("%.3f", r.rtt.Seconds()*1000),
				"OK",
			)
		}
	}

	t.Print()
	fmt.Println()
	stats.print(host)
}

// resolve performs DNS lookup for a hostname, returning the IPv4 address.
// We use net.LookupIP here as it's the minimal way to do DNS resolution.
// Implementing DNS from scratch would require constructing DNS packets
// and querying UDP port 53, which is beyond the scope of learning ICMP/IP.
func resolve(host string) ([4]byte, error) {
	// Try to parse as IP address first
	ip := parseIPv4(host)
	if ip[0] != 0 || ip[1] != 0 || ip[2] != 0 || ip[3] != 0 {
		return ip, nil
	}

	// If not an IP, we need DNS resolution
	// This is the ONE minimal use of net package for DNS
	// (implementing DNS ourselves would require significant additional code)
	ips, err := net.LookupIP(host)
	if err != nil {
		return [4]byte{}, err
	}

	// Find first IPv4 address
	for _, netIP := range ips {
		if ipv4 := netIP.To4(); ipv4 != nil {
			var result [4]byte
			copy(result[:], ipv4)
			return result, nil
		}
	}

	return [4]byte{}, fmt.Errorf("no IPv4 address found for %s", host)
}

// parseIPv4 attempts to parse a dotted-quad IP address like "192.168.1.1"
func parseIPv4(s string) [4]byte {
	var ip [4]byte
	var octet, pos int

	for i := 0; i < len(s) && pos < 4; i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			octet = octet*10 + int(c-'0')
			if octet > 255 {
				return [4]byte{} // invalid
			}
		} else if c == '.' {
			ip[pos] = byte(octet)
			pos++
			octet = 0
		} else {
			return [4]byte{} // invalid character
		}
	}

	if pos == 3 {
		ip[3] = byte(octet)
		return ip
	}

	return [4]byte{} // didn't parse correctly
}

// ipToString converts a [4]byte IP to dotted-quad notation
func ipToString(ip [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func sendEchoRequest(fd int, dstIP [4]byte, id, seq uint16, payloadSize int) error {
	// Build ICMP echo request
	icmpMsg := &ICMP{
		Type: ICMPTypeEchoRequest,
		Code: 0,
		ID:   id,
		Seq:  seq,
		Data: make([]byte, payloadSize),
	}

	// Fill payload with a pattern (timestamp + padding)
	now := time.Now().UnixNano()
	if len(icmpMsg.Data) >= 8 {
		binary.BigEndian.PutUint64(icmpMsg.Data[0:8], uint64(now))
	}
	for i := 8; i < len(icmpMsg.Data); i++ {
		icmpMsg.Data[i] = byte(i)
	}

	icmpBytes := icmpMsg.Marshal()

	// Construct sockaddr for destination
	sa := &syscall.SockaddrInet4{
		Port: 0, // not used for ICMP
		Addr: dstIP,
	}

	// Send using raw syscall
	return syscall.Sendto(fd, icmpBytes, 0, sa)
}

func receiveEchoReply(fd int, expectedID, expectedSeq uint16, timeout time.Duration) (*ICMP, [4]byte, time.Duration, error) {
	// Set socket timeout
	tv := syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int64((timeout % time.Second) / time.Microsecond),
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, [4]byte{}, 0, err
	}

	buf := make([]byte, 1500)
	start := time.Now()

	for {
		// Receive packet using raw syscall
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, [4]byte{}, 0, err
		}

		// Extract source IP from sockaddr
		var srcIP [4]byte
		if sa, ok := from.(*syscall.SockaddrInet4); ok {
			srcIP = sa.Addr
		}

		// On Linux with SOCK_RAW IPPROTO_ICMP, we get IP header + ICMP
		// Parse the IP header to find where ICMP starts
		if n < 20 {
			continue // too short for IP header
		}

		ipHdr, err := ipv4.Unmarshal(buf[:n])
		if err != nil {
			continue
		}

		// IHL tells us header length in 32-bit words
		ihl := int(ipHdr.VerIHL & 0x0F)
		headerLen := ihl * 4

		if n < headerLen {
			continue
		}

		// ICMP payload starts after IP header
		icmpPayload := buf[headerLen:n]
		if len(icmpPayload) < 8 {
			continue
		}

		icmpMsg, err := UnmarshalICMP(icmpPayload)
		if err != nil {
			continue
		}

		// Check if this is our echo reply
		if icmpMsg.Type == ICMPTypeEchoReply &&
			icmpMsg.ID == expectedID &&
			icmpMsg.Seq == expectedSeq {
			rtt := time.Since(start)
			return icmpMsg, srcIP, rtt, nil
		}

		// Not our packet, keep waiting
		remaining := timeout - time.Since(start)
		if remaining <= 0 {
			return nil, [4]byte{}, 0, syscall.ETIMEDOUT
		}

		// Update timeout for next receive
		tv.Sec = int64(remaining / time.Second)
		tv.Usec = int64((remaining % time.Second) / time.Microsecond)
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	}
}

// pingStats tracks packet loss and RTT statistics
type pingStats struct {
	sent      int
	received  int
	minRTT    time.Duration
	maxRTT    time.Duration
	totalRTT  time.Duration
}

func (s *pingStats) recordSuccess(rtt time.Duration) {
	s.sent++
	s.received++
	s.totalRTT += rtt

	if s.received == 1 || rtt < s.minRTT {
		s.minRTT = rtt
	}
	if rtt > s.maxRTT {
		s.maxRTT = rtt
	}
}

func (s *pingStats) recordLoss() {
	s.sent++
}

func (s *pingStats) print(host string) {
	loss := 0.0
	if s.sent > 0 {
		loss = float64(s.sent-s.received) / float64(s.sent) * 100
	}

	// Create statistics table
	headers := []string{"STATISTICS - " + host}
	t := tables.NewFromStrings(headers...)
	
	t.AddRow(fmt.Sprintf("Packets Transmitted: %d", s.sent))
	t.AddRow(fmt.Sprintf("Packets Received: %d", s.received))
	t.AddRow(fmt.Sprintf("Packet Loss: %.1f%%", loss))
	
	if s.received > 0 {
		avg := s.totalRTT / time.Duration(s.received)
		t.AddRow(fmt.Sprintf("Min RTT: %.3f ms", s.minRTT.Seconds()*1000))
		t.AddRow(fmt.Sprintf("Avg RTT: %.3f ms", avg.Seconds()*1000))
		t.AddRow(fmt.Sprintf("Max RTT: %.3f ms", s.maxRTT.Seconds()*1000))
	}
	
	t.Print()
	fmt.Println()
}

