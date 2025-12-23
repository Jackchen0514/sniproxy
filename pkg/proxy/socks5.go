package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

// SOCKS5 constants
const (
	socks5Version = 0x05

	// Authentication methods
	socks5AuthNone     = 0x00
	socks5AuthPassword = 0x02
	socks5AuthNoAccept = 0xFF

	// Commands
	socks5CmdConnect = 0x01

	// Address types
	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04

	// Reply codes
	socks5ReplySuccess = 0x00
)

// SOCKS5 errors
var (
	ErrInvalidProxyURL     = errors.New("invalid proxy URL")
	ErrUnsupportedScheme   = errors.New("unsupported proxy scheme (only socks5 supported)")
	ErrAuthFailed          = errors.New("SOCKS5 authentication failed")
	ErrConnectionFailed    = errors.New("SOCKS5 connection to target failed")
	ErrUnsupportedAuthMethod = errors.New("SOCKS5 server requires unsupported authentication")
)

// SOCKS5Dialer provides SOCKS5 proxy connection functionality
type SOCKS5Dialer struct {
	proxyAddr string
	username  string
	password  string
	timeout   time.Duration
}

// NewSOCKS5Dialer creates a new SOCKS5 dialer from a proxy URL
// Supports: socks5://host:port or socks5://user:pass@host:port
func NewSOCKS5Dialer(proxyURL string, timeout time.Duration) (*SOCKS5Dialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProxyURL, err)
	}

	if u.Scheme != "socks5" {
		return nil, ErrUnsupportedScheme
	}

	dialer := &SOCKS5Dialer{
		proxyAddr: u.Host,
		timeout:   timeout,
	}

	if u.User != nil {
		dialer.username = u.User.Username()
		dialer.password, _ = u.User.Password()
	}

	return dialer, nil
}

// DialContext connects to the target address through the SOCKS5 proxy
func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Parse target address
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Connect to SOCKS5 proxy
	dialer := &net.Dialer{Timeout: d.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// Set deadline for handshake
	if d.timeout > 0 {
		conn.SetDeadline(time.Now().Add(d.timeout))
	}

	// Perform SOCKS5 handshake
	if err := d.handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Send connect request
	if err := d.connect(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}

	// Clear deadline after successful connection
	conn.SetDeadline(time.Time{})

	return conn, nil
}

// handshake performs SOCKS5 authentication handshake
func (d *SOCKS5Dialer) handshake(conn net.Conn) error {
	// Build auth methods request
	var authMethods []byte
	if d.username != "" {
		authMethods = []byte{socks5AuthNone, socks5AuthPassword}
	} else {
		authMethods = []byte{socks5AuthNone}
	}

	// Send: VER | NMETHODS | METHODS
	req := make([]byte, 2+len(authMethods))
	req[0] = socks5Version
	req[1] = byte(len(authMethods))
	copy(req[2:], authMethods)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	// Read: VER | METHOD
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[0] != socks5Version {
		return fmt.Errorf("unexpected SOCKS version: %d", resp[0])
	}

	switch resp[1] {
	case socks5AuthNone:
		// No authentication required
		return nil

	case socks5AuthPassword:
		// Username/password authentication
		return d.authenticatePassword(conn)

	case socks5AuthNoAccept:
		return ErrUnsupportedAuthMethod

	default:
		return fmt.Errorf("unsupported auth method: %d", resp[1])
	}
}

// authenticatePassword performs username/password authentication
func (d *SOCKS5Dialer) authenticatePassword(conn net.Conn) error {
	// Send: VER | ULEN | UNAME | PLEN | PASSWD
	req := make([]byte, 3+len(d.username)+len(d.password))
	req[0] = 0x01 // Auth sub-version
	req[1] = byte(len(d.username))
	copy(req[2:], d.username)
	req[2+len(d.username)] = byte(len(d.password))
	copy(req[3+len(d.username):], d.password)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to send auth credentials: %w", err)
	}

	// Read: VER | STATUS
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read auth result: %w", err)
	}

	if resp[1] != 0x00 {
		return ErrAuthFailed
	}

	return nil
}

// connect sends SOCKS5 connect request
func (d *SOCKS5Dialer) connect(conn net.Conn, host string, port int) error {
	// Build connect request
	// VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
	var req []byte

	// Check if host is an IP address
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			req = make([]byte, 10)
			req[3] = socks5AddrIPv4
			copy(req[4:8], ip4)
			binary.BigEndian.PutUint16(req[8:], uint16(port))
		} else {
			// IPv6
			req = make([]byte, 22)
			req[3] = socks5AddrIPv6
			copy(req[4:20], ip.To16())
			binary.BigEndian.PutUint16(req[20:], uint16(port))
		}
	} else {
		// Domain name
		if len(host) > 255 {
			return fmt.Errorf("domain name too long: %d", len(host))
		}
		req = make([]byte, 7+len(host))
		req[3] = socks5AddrDomain
		req[4] = byte(len(host))
		copy(req[5:], host)
		binary.BigEndian.PutUint16(req[5+len(host):], uint16(port))
	}

	req[0] = socks5Version
	req[1] = socks5CmdConnect
	req[2] = 0x00 // Reserved

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to send connect request: %w", err)
	}

	// Read response header: VER | REP | RSV | ATYP
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read connect response: %w", err)
	}

	if resp[0] != socks5Version {
		return fmt.Errorf("unexpected SOCKS version in response: %d", resp[0])
	}

	if resp[1] != socks5ReplySuccess {
		return fmt.Errorf("%w: reply code %d", ErrConnectionFailed, resp[1])
	}

	// Read and discard bound address
	var addrLen int
	switch resp[3] {
	case socks5AddrIPv4:
		addrLen = 4 + 2 // IPv4 + port
	case socks5AddrIPv6:
		addrLen = 16 + 2 // IPv6 + port
	case socks5AddrDomain:
		// Read domain length
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		addrLen = int(lenBuf[0]) + 2 // domain + port
	default:
		return fmt.Errorf("unknown address type: %d", resp[3])
	}

	// Discard the bound address
	if _, err := io.ReadFull(conn, make([]byte, addrLen)); err != nil {
		return fmt.Errorf("failed to read bound address: %w", err)
	}

	return nil
}
