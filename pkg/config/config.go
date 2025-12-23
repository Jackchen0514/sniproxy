// Package config provides configuration management for the SNI proxy.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	// Server configuration
	Listen      string        `yaml:"listen"`       // Address to listen on (e.g., ":443")
	DefaultPort int           `yaml:"default_port"` // Default upstream port if not specified

	// Timeouts
	ConnectTimeout time.Duration `yaml:"connect_timeout"` // Timeout for connecting to upstream
	IdleTimeout    time.Duration `yaml:"idle_timeout"`    // Idle connection timeout

	// Access control
	AllowedHosts []string `yaml:"allowed_hosts"` // Whitelist of allowed hostnames (supports wildcards)
	DeniedHosts  []string `yaml:"denied_hosts"`  // Blacklist of denied hostnames (supports wildcards)

	// Routing
	Routes []Route `yaml:"routes"` // Custom routing rules

	// Logging
	LogLevel string `yaml:"log_level"` // Log level: debug, info, warn, error
	LogFile  string `yaml:"log_file"`  // Log file path (empty for stdout)

	// Performance
	BufferSize    int `yaml:"buffer_size"`    // Buffer size for data transfer
	MaxConcurrent int `yaml:"max_concurrent"` // Maximum concurrent connections
}

// Route defines a custom routing rule
type Route struct {
	Match  string `yaml:"match"`  // Hostname pattern to match (supports wildcards)
	Target string `yaml:"target"` // Target address (host:port), empty means use SNI hostname
	Proxy  string `yaml:"proxy"`  // Proxy URL (e.g., socks5://127.0.0.1:40000), empty means direct
}

// RouteResult contains the routing decision for a hostname
type RouteResult struct {
	Target string // Target address (host:port)
	Proxy  string // Proxy URL (empty = direct connection)
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Listen:         ":443",
		DefaultPort:    443,
		ConnectTimeout: 10 * time.Second,
		IdleTimeout:    60 * time.Second,
		AllowedHosts:   nil, // Allow all if empty
		DeniedHosts:    nil,
		Routes:         nil,
		LogLevel:       "info",
		LogFile:        "",
		BufferSize:     32 * 1024, // 32KB
		MaxConcurrent:  10000,
	}
}

// Load reads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address is required")
	}

	if c.DefaultPort <= 0 || c.DefaultPort > 65535 {
		return fmt.Errorf("default_port must be between 1 and 65535")
	}

	if c.ConnectTimeout <= 0 {
		return fmt.Errorf("connect_timeout must be positive")
	}

	if c.IdleTimeout <= 0 {
		return fmt.Errorf("idle_timeout must be positive")
	}

	if c.BufferSize <= 0 {
		return fmt.Errorf("buffer_size must be positive")
	}

	if c.MaxConcurrent <= 0 {
		return fmt.Errorf("max_concurrent must be positive")
	}

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[strings.ToLower(c.LogLevel)] {
		return fmt.Errorf("invalid log_level: %s", c.LogLevel)
	}

	return nil
}

// IsHostAllowed checks if a hostname is allowed by the access control rules
func (c *Config) IsHostAllowed(hostname string) bool {
	hostname = strings.ToLower(hostname)

	// Check denied list first
	for _, pattern := range c.DeniedHosts {
		if matchHostPattern(pattern, hostname) {
			return false
		}
	}

	// If allowed list is empty, allow all (except denied)
	if len(c.AllowedHosts) == 0 {
		return true
	}

	// Check allowed list
	for _, pattern := range c.AllowedHosts {
		if matchHostPattern(pattern, hostname) {
			return true
		}
	}

	return false
}

// GetRouteForHost returns the routing decision for a given hostname
func (c *Config) GetRouteForHost(hostname string) RouteResult {
	hostname = strings.ToLower(hostname)
	defaultTarget := fmt.Sprintf("%s:%d", hostname, c.DefaultPort)

	// Check custom routes first
	for _, route := range c.Routes {
		if matchHostPattern(route.Match, hostname) {
			target := route.Target
			if target == "" {
				target = defaultTarget
			}
			return RouteResult{
				Target: target,
				Proxy:  route.Proxy,
			}
		}
	}

	// Default: direct connection to hostname with default port
	return RouteResult{
		Target: defaultTarget,
		Proxy:  "",
	}
}

// matchHostPattern checks if a hostname matches a pattern (supports wildcards)
func matchHostPattern(pattern, hostname string) bool {
	pattern = strings.ToLower(pattern)

	// Exact match
	if pattern == hostname {
		return true
	}

	// Wildcard prefix match (*.example.com)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Keep the dot
		return strings.HasSuffix(hostname, suffix)
	}

	// Wildcard suffix match (example.*)
	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-1] // Keep the dot
		return strings.HasPrefix(hostname, prefix)
	}

	return false
}
