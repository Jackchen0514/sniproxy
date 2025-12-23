// SNI Proxy - A transparent TLS proxy based on Server Name Indication
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sniproxy/pkg/config"
	"github.com/sniproxy/pkg/proxy"
)

var (
	version   = "1.0.0"
	buildTime = "unknown"
)

func main() {
	// Command line flags
	configFile := flag.String("config", "", "Path to configuration file")
	listenAddr := flag.String("listen", ":443", "Address to listen on")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	showVersion := flag.Bool("version", false, "Show version information")
	showHelp := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("SNI Proxy v%s (built: %s)\n", version, buildTime)
		os.Exit(0)
	}

	// Load configuration
	var cfg *config.Config
	var err error

	if *configFile != "" {
		cfg, err = config.Load(*configFile)
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}
		log.Printf("Loaded configuration from %s", *configFile)
	} else {
		cfg = config.DefaultConfig()
		// Override with command line flags
		cfg.Listen = *listenAddr
		cfg.LogLevel = *logLevel
	}

	// Create and start the server
	server := proxy.New(cfg)

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Wait for signal or error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		if err := server.Shutdown(30 * time.Second); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}

	// Print final statistics
	stats := server.GetStats()
	log.Printf("Final statistics:")
	log.Printf("  Total connections: %d", stats.TotalConnections)
	log.Printf("  Failed connections: %d", stats.FailedConnections)
	log.Printf("  Rejected connections: %d", stats.RejectedConnections)
	log.Printf("  Bytes sent: %d", stats.BytesSent)
	log.Printf("  Bytes received: %d", stats.BytesReceived)
}

func printHelp() {
	fmt.Printf(`SNI Proxy v%s - A transparent TLS proxy based on Server Name Indication

USAGE:
    sniproxy [OPTIONS]

OPTIONS:
    -config <file>      Path to YAML configuration file
    -listen <addr>      Address to listen on (default: :443)
    -log-level <level>  Log level: debug, info, warn, error (default: info)
    -version            Show version information
    -help               Show this help message

EXAMPLES:
    # Start with default settings (listen on :443)
    sniproxy

    # Start with custom listen address
    sniproxy -listen :8443

    # Start with configuration file
    sniproxy -config /etc/sniproxy/config.yaml

    # Start with debug logging
    sniproxy -log-level debug

CONFIGURATION FILE:
    The configuration file uses YAML format. Example:

    listen: ":443"
    default_port: 443
    connect_timeout: 10s
    idle_timeout: 60s
    log_level: info

    allowed_hosts:
      - "*.example.com"
      - "api.myservice.io"

    denied_hosts:
      - "blocked.example.com"

    routes:
      - match: "*.internal.example.com"
        target: "internal-lb:443"

For more information, see: https://github.com/sniproxy/sniproxy

`, version)
}
