// Package proxyproto provides PROXY protocol header generation for backend connections.
// PROXY protocol preserves client connection information when proxying connections.
package proxyproto

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Version specifies PROXY protocol version.
type Version int

const (
	// V1 is the text-based PROXY protocol v1
	V1 Version = 1
	// V2 is the binary PROXY protocol v2
	V2 Version = 2
)

// Header represents a PROXY protocol header.
type Header struct {
	Version           Version
	SourceAddr        net.Addr
	DestinationAddr   net.Addr
	TransportProtocol Protocol
}

// Protocol is the transport protocol type.
type Protocol byte

const (
	// TCPv4 is TCP over IPv4
	TCPv4 Protocol = 0x11
	// TCPv6 is TCP over IPv6
	TCPv6 Protocol = 0x21
	// UDPv4 is UDP over IPv4
	UDPv4 Protocol = 0x12
	// UDPv6 is UDP over IPv6
	UDPv6 Protocol = 0x22
	// Unknown is used for Unix sockets or unsupported protocols
	Unknown Protocol = 0x00
)

// WriteTo writes the PROXY protocol header to the connection.
func (h *Header) WriteTo(conn net.Conn) (int64, error) {
	switch h.Version {
	case V1:
		return h.writeV1(conn)
	case V2:
		return h.writeV2(conn)
	default:
		return 0, fmt.Errorf("proxyproto: unsupported version %d", h.Version)
	}
}

// writeV1 writes PROXY protocol v1 header (text format).
// Format: PROXY TCP4/TCP6/UNKNOWN src_addr dst_addr src_port dst_port\r\n
func (h *Header) writeV1(conn net.Conn) (int64, error) {
	var srcIP, dstIP, srcPort, dstPort, proto string

	srcAddr, srcOk := h.SourceAddr.(*net.TCPAddr)
	dstAddr, dstOk := h.DestinationAddr.(*net.TCPAddr)

	if !srcOk || !dstOk {
		// Unknown protocol - use PROXY UNKNOWN
		n, err := conn.Write([]byte("PROXY UNKNOWN\r\n"))
		return int64(n), err
	}

	if srcAddr.IP.To4() != nil && dstAddr.IP.To4() != nil {
		proto = "TCP4"
		srcIP = srcAddr.IP.To4().String()
		dstIP = dstAddr.IP.To4().String()
	} else {
		proto = "TCP6"
		srcIP = srcAddr.IP.String()
		dstIP = dstAddr.IP.String()
	}

	srcPort = fmt.Sprintf("%d", srcAddr.Port)
	dstPort = fmt.Sprintf("%d", dstAddr.Port)

	header := fmt.Sprintf("PROXY %s %s %s %s %s\r\n", proto, srcIP, dstIP, srcPort, dstPort)
	n, err := conn.Write([]byte(header))
	return int64(n), err
}

// writeV2 writes PROXY protocol v2 header (binary format).
func (h *Header) writeV2(conn net.Conn) (int64, error) {
	// Signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A (12 bytes)
	header := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

	// Version (4 bits) + Command (4 bits)
	// Version: 2 (0x2), Command: PROXY (0x1)
	header = append(header, 0x21) // v2 + PROXY

	// Address family (4 bits) + Transport protocol (4 bits)
	// Determine from source address
	var addrFamily byte
	var addrData []byte

	srcAddr, srcOk := h.SourceAddr.(*net.TCPAddr)
	dstAddr, dstOk := h.DestinationAddr.(*net.TCPAddr)

	if !srcOk || !dstOk {
		// Unknown address family
		header = append(header, 0x00) // UNSPEC + UNSPEC
		// Address length: 0
		header = append(header, 0x00, 0x00)
	} else {
		if srcAddr.IP.To4() != nil && dstAddr.IP.To4() != nil {
			addrFamily = 0x10 // AF_INET + STREAM
			// IPv4 addresses: 4 + 4 + 2 + 2 = 12 bytes
			addrData = make([]byte, 12)
			copy(addrData[0:4], srcAddr.IP.To4())
			copy(addrData[4:8], dstAddr.IP.To4())
			binary.BigEndian.PutUint16(addrData[8:10], uint16(srcAddr.Port))
			binary.BigEndian.PutUint16(addrData[10:12], uint16(dstAddr.Port))
		} else {
			addrFamily = 0x20 // AF_INET6 + STREAM
			// IPv6 addresses: 16 + 16 + 2 + 2 = 36 bytes
			addrData = make([]byte, 36)
			copy(addrData[0:16], srcAddr.IP.To16())
			copy(addrData[16:32], dstAddr.IP.To16())
			binary.BigEndian.PutUint16(addrData[32:34], uint16(srcAddr.Port))
			binary.BigEndian.PutUint16(addrData[34:36], uint16(dstAddr.Port))
		}

		header = append(header, addrFamily)
		// Address length (2 bytes, big-endian)
		header = append(header, byte(len(addrData)>>8), byte(len(addrData)))
		header = append(header, addrData...)
	}

	n, err := conn.Write(header)
	return int64(n), err
}

// NewHeader creates a new PROXY protocol header for the given connection.
func NewHeader(version Version, srcAddr, dstAddr net.Addr, proto Protocol) (*Header, error) {
	return &Header{
		Version:           version,
		SourceAddr:        srcAddr,
		DestinationAddr:   dstAddr,
		TransportProtocol: proto,
	}, nil
}

// WriteHeader writes a PROXY protocol header to the connection.
// This is a convenience function that creates and writes the header.
func WriteHeader(conn net.Conn, version Version) error {
	var proto Protocol
	if _, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if conn.RemoteAddr().(*net.TCPAddr).IP.To4() != nil {
			proto = TCPv4
		} else {
			proto = TCPv6
		}
	} else {
		proto = Unknown
	}

	header, err := NewHeader(version, conn.RemoteAddr(), conn.LocalAddr(), proto)
	if err != nil {
		return err
	}

	_, err = header.WriteTo(conn)
	return err
}