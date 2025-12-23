// Package proxy provides the core SNI proxy server functionality.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sniproxy/pkg/config"
	"github.com/sniproxy/pkg/sni"
)

// Server represents the SNI proxy server
type Server struct {
	config   *config.Config
	listener net.Listener
	logger   *Logger

	// Statistics
	stats Stats

	// Connection management
	activeConns sync.WaitGroup
	connCount   int64
	semaphore   chan struct{}

	// Shutdown
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	mu             sync.Mutex
	running        bool
}

// Stats contains server statistics
type Stats struct {
	TotalConnections   int64
	ActiveConnections  int64
	BytesSent          int64
	BytesReceived      int64
	FailedConnections  int64
	RejectedConnections int64
}

// Logger provides leveled logging
type Logger struct {
	level  string
	logger *log.Logger
}

// NewLogger creates a new logger
func NewLogger(level string, output io.Writer) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(output, "", log.LstdFlags),
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level == "debug" {
		l.logger.Printf("[DEBUG] "+format, args...)
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.level == "debug" || l.level == "info" {
		l.logger.Printf("[INFO] "+format, args...)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level != "error" {
		l.logger.Printf("[WARN] "+format, args...)
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.logger.Printf("[ERROR] "+format, args...)
}

// New creates a new SNI proxy server
func New(cfg *config.Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:         cfg,
		logger:         NewLogger(cfg.LogLevel, log.Writer()),
		semaphore:      make(chan struct{}, cfg.MaxConcurrent),
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
}

// Start starts the proxy server
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to start listener: %w", err)
	}

	s.listener = listener
	s.running = true
	s.mu.Unlock()

	s.logger.Info("SNI Proxy started on %s", s.config.Listen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownCtx.Done():
				return nil
			default:
				s.logger.Error("Failed to accept connection: %v", err)
				continue
			}
		}

		// Check connection limit
		select {
		case s.semaphore <- struct{}{}:
			s.activeConns.Add(1)
			go s.handleConnection(conn)
		default:
			s.logger.Warn("Connection limit reached, rejecting connection from %s", conn.RemoteAddr())
			atomic.AddInt64(&s.stats.RejectedConnections, 1)
			conn.Close()
		}
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(timeout time.Duration) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	s.logger.Info("Shutting down server...")
	s.shutdownCancel()

	if s.listener != nil {
		s.listener.Close()
	}

	// Wait for active connections with timeout
	done := make(chan struct{})
	go func() {
		s.activeConns.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("All connections closed gracefully")
	case <-time.After(timeout):
		s.logger.Warn("Shutdown timeout reached, forcing close")
	}

	return nil
}

// GetStats returns current server statistics
func (s *Server) GetStats() Stats {
	return Stats{
		TotalConnections:    atomic.LoadInt64(&s.stats.TotalConnections),
		ActiveConnections:   atomic.LoadInt64(&s.stats.ActiveConnections),
		BytesSent:           atomic.LoadInt64(&s.stats.BytesSent),
		BytesReceived:       atomic.LoadInt64(&s.stats.BytesReceived),
		FailedConnections:   atomic.LoadInt64(&s.stats.FailedConnections),
		RejectedConnections: atomic.LoadInt64(&s.stats.RejectedConnections),
	}
}

// handleConnection handles a single client connection
func (s *Server) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		<-s.semaphore
		s.activeConns.Done()
		atomic.AddInt64(&s.stats.ActiveConnections, -1)
	}()

	atomic.AddInt64(&s.stats.TotalConnections, 1)
	atomic.AddInt64(&s.stats.ActiveConnections, 1)

	clientAddr := clientConn.RemoteAddr().String()
	s.logger.Debug("New connection from %s", clientAddr)

	// Set read deadline for the initial handshake
	clientConn.SetReadDeadline(time.Now().Add(s.config.ConnectTimeout))

	// Parse SNI from ClientHello
	clientHello, err := sni.PeekClientHello(clientConn)
	if err != nil {
		s.logger.Debug("Failed to parse ClientHello from %s: %v", clientAddr, err)
		atomic.AddInt64(&s.stats.FailedConnections, 1)
		return
	}

	serverName := clientHello.ServerName
	s.logger.Debug("SNI: %s from %s", serverName, clientAddr)

	// Check access control
	if !s.config.IsHostAllowed(serverName) {
		s.logger.Warn("Access denied for %s to %s", clientAddr, serverName)
		atomic.AddInt64(&s.stats.RejectedConnections, 1)
		return
	}

	// Get routing decision
	route := s.config.GetRouteForHost(serverName)
	target := route.Target

	// Connect to upstream server (directly or via proxy)
	var upstreamConn net.Conn

	if route.Proxy != "" {
		// Connect via SOCKS5 proxy
		s.logger.Debug("Connecting to %s via proxy %s", target, route.Proxy)

		socks5Dialer, err := NewSOCKS5Dialer(route.Proxy, s.config.ConnectTimeout)
		if err != nil {
			s.logger.Error("Failed to create SOCKS5 dialer for %s: %v", route.Proxy, err)
			atomic.AddInt64(&s.stats.FailedConnections, 1)
			return
		}

		upstreamConn, err = socks5Dialer.DialContext(s.shutdownCtx, "tcp", target)
		if err != nil {
			s.logger.Error("Failed to connect to %s via proxy %s: %v", target, route.Proxy, err)
			atomic.AddInt64(&s.stats.FailedConnections, 1)
			return
		}
	} else {
		// Direct connection
		s.logger.Debug("Connecting directly to upstream %s", target)

		dialer := &net.Dialer{
			Timeout: s.config.ConnectTimeout,
		}

		var err error
		upstreamConn, err = dialer.DialContext(s.shutdownCtx, "tcp", target)
		if err != nil {
			s.logger.Error("Failed to connect to upstream %s: %v", target, err)
			atomic.AddInt64(&s.stats.FailedConnections, 1)
			return
		}
	}
	defer upstreamConn.Close()

	if route.Proxy != "" {
		s.logger.Info("Proxying %s -> %s (via %s)", clientAddr, target, route.Proxy)
	} else {
		s.logger.Info("Proxying %s -> %s (direct)", clientAddr, target)
	}

	// Clear the deadline for the data transfer phase
	clientConn.SetReadDeadline(time.Time{})

	// Forward the original ClientHello to upstream
	if _, err := upstreamConn.Write(clientHello.RawClientHello); err != nil {
		s.logger.Error("Failed to forward ClientHello to upstream: %v", err)
		atomic.AddInt64(&s.stats.FailedConnections, 1)
		return
	}

	// Bidirectional data transfer
	s.relay(clientConn, upstreamConn)
}

// relay performs bidirectional data transfer between client and upstream
func (s *Server) relay(client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Upstream
	go func() {
		defer wg.Done()
		sent := s.copy(upstream, client, "client->upstream")
		atomic.AddInt64(&s.stats.BytesSent, sent)
		// Signal upstream that client is done writing
		if tcpConn, ok := upstream.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Upstream -> Client
	go func() {
		defer wg.Done()
		received := s.copy(client, upstream, "upstream->client")
		atomic.AddInt64(&s.stats.BytesReceived, received)
		// Signal client that upstream is done writing
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}

// copy copies data from src to dst and returns bytes copied
func (s *Server) copy(dst, src net.Conn, direction string) int64 {
	buf := make([]byte, s.config.BufferSize)
	var total int64

	for {
		// Set idle timeout
		src.SetReadDeadline(time.Now().Add(s.config.IdleTimeout))

		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			if written > 0 {
				total += int64(written)
			}
			if writeErr != nil {
				s.logger.Debug("Write error (%s): %v", direction, writeErr)
				break
			}
			if written != n {
				s.logger.Debug("Short write (%s): wrote %d of %d", direction, written, n)
				break
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				// Check if it's a timeout
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					s.logger.Debug("Connection timeout (%s)", direction)
				} else {
					s.logger.Debug("Read error (%s): %v", direction, readErr)
				}
			}
			break
		}
	}

	return total
}
