// Package sni provides functionality to parse SNI (Server Name Indication)
// from TLS ClientHello messages.
package sni

import (
	"errors"
	"io"
)

// TLS record types
const (
	recordTypeHandshake = 0x16
)

// TLS handshake types
const (
	handshakeTypeClientHello = 0x01
)

// TLS extension types
const (
	extensionServerName = 0x00
)

// Errors
var (
	ErrNotTLS            = errors.New("not a TLS handshake")
	ErrNotClientHello    = errors.New("not a ClientHello message")
	ErrNoSNI             = errors.New("no SNI extension found")
	ErrInvalidSNI        = errors.New("invalid SNI extension")
	ErrBufferTooSmall    = errors.New("buffer too small to contain valid TLS record")
	ErrRecordTooLarge    = errors.New("TLS record too large")
	ErrInvalidHostname   = errors.New("invalid hostname in SNI")
)

// ClientHelloInfo contains information extracted from a TLS ClientHello message
type ClientHelloInfo struct {
	ServerName    string
	RawClientHello []byte
}

// PeekClientHello reads just enough data to extract the SNI from a TLS ClientHello.
// It returns the ClientHelloInfo and the raw bytes that were read (which must be
// forwarded to the upstream server).
func PeekClientHello(reader io.Reader) (*ClientHelloInfo, error) {
	// Read TLS record header (5 bytes)
	// Byte 0: Content type
	// Bytes 1-2: Version
	// Bytes 3-4: Length
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	// Check if this is a TLS handshake record
	if header[0] != recordTypeHandshake {
		return nil, ErrNotTLS
	}

	// Get record length
	recordLength := int(header[3])<<8 | int(header[4])
	if recordLength > 16384 {
		return nil, ErrRecordTooLarge
	}

	// Read the full handshake record
	record := make([]byte, recordLength)
	if _, err := io.ReadFull(reader, record); err != nil {
		return nil, err
	}

	// Combine header and record for the raw ClientHello
	rawData := make([]byte, 5+recordLength)
	copy(rawData, header)
	copy(rawData[5:], record)

	// Parse the handshake message
	serverName, err := parseClientHello(record)
	if err != nil {
		return nil, err
	}

	return &ClientHelloInfo{
		ServerName:    serverName,
		RawClientHello: rawData,
	}, nil
}

// parseClientHello parses a TLS ClientHello message and extracts the SNI
func parseClientHello(data []byte) (string, error) {
	if len(data) < 4 {
		return "", ErrBufferTooSmall
	}

	// Check handshake type
	if data[0] != handshakeTypeClientHello {
		return "", ErrNotClientHello
	}

	// Get handshake length (3 bytes)
	handshakeLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+handshakeLen {
		return "", ErrBufferTooSmall
	}

	// Move past handshake header
	pos := 4

	// Skip client version (2 bytes)
	pos += 2
	if pos > len(data) {
		return "", ErrBufferTooSmall
	}

	// Skip random (32 bytes)
	pos += 32
	if pos > len(data) {
		return "", ErrBufferTooSmall
	}

	// Skip session ID
	if pos >= len(data) {
		return "", ErrBufferTooSmall
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos > len(data) {
		return "", ErrBufferTooSmall
	}

	// Skip cipher suites
	if pos+2 > len(data) {
		return "", ErrBufferTooSmall
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen
	if pos > len(data) {
		return "", ErrBufferTooSmall
	}

	// Skip compression methods
	if pos >= len(data) {
		return "", ErrBufferTooSmall
	}
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen
	if pos > len(data) {
		return "", ErrBufferTooSmall
	}

	// Check if there are extensions
	if pos+2 > len(data) {
		return "", ErrNoSNI
	}

	// Get extensions length
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+extensionsLen > len(data) {
		return "", ErrBufferTooSmall
	}

	// Parse extensions
	extensionsEnd := pos + extensionsLen
	for pos+4 <= extensionsEnd {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extLen > extensionsEnd {
			return "", ErrBufferTooSmall
		}

		if extType == extensionServerName {
			return parseServerNameExtension(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return "", ErrNoSNI
}

// parseServerNameExtension parses the SNI extension data
func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", ErrInvalidSNI
	}

	// Get server name list length
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return "", ErrInvalidSNI
	}

	pos := 2
	listEnd := 2 + listLen

	for pos+3 <= listEnd {
		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if pos+nameLen > listEnd {
			return "", ErrInvalidSNI
		}

		// Name type 0 is hostname
		if nameType == 0 {
			hostname := string(data[pos : pos+nameLen])
			if !isValidHostname(hostname) {
				return "", ErrInvalidHostname
			}
			return hostname, nil
		}

		pos += nameLen
	}

	return "", ErrNoSNI
}

// isValidHostname performs basic validation on the hostname
func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	for _, c := range hostname {
		if !((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '.') {
			return false
		}
	}

	return true
}
