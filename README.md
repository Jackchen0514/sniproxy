# SNI Proxy

A high-performance, transparent TLS proxy written in Go that routes traffic based on Server Name Indication (SNI).

## Features

- **Transparent Proxying**: Routes TLS traffic without decrypting it, based on the SNI extension in TLS ClientHello
- **Access Control**: Whitelist and blacklist support with wildcard patterns
- **Custom Routing**: Define custom routing rules to direct traffic to different backends
- **High Performance**: Non-blocking I/O with configurable connection limits and buffer sizes
- **Graceful Shutdown**: Properly handles termination signals with connection draining
- **Statistics**: Tracks connection counts, bytes transferred, and error rates
- **Flexible Configuration**: YAML configuration file or command-line flags

## How It Works

SNI (Server Name Indication) is a TLS extension that allows clients to specify the target hostname during the TLS handshake. This proxy:

1. Accepts incoming TLS connections
2. Parses the TLS ClientHello message to extract the SNI hostname
3. Checks access control rules (allow/deny lists)
4. Connects to the upstream server (based on SNI or custom routes)
5. Forwards the original ClientHello and all subsequent traffic bidirectionally

Since the proxy operates at the TLS layer without decryption, it cannot inspect the encrypted payload - it only reads the unencrypted SNI extension.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/sniproxy/sniproxy.git
cd sniproxy

# Build
go build -o sniproxy ./cmd/sniproxy

# Install (optional)
go install ./cmd/sniproxy
```

### Using Go Install

```bash
go install github.com/sniproxy/sniproxy/cmd/sniproxy@latest
```

## Usage

### Basic Usage

```bash
# Start with default settings (listen on :443)
sudo sniproxy

# Start on a custom port
sniproxy -listen :8443

# Start with a configuration file
sniproxy -config /etc/sniproxy/config.yaml

# Start with debug logging
sniproxy -log-level debug
```

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `-config` | | Path to YAML configuration file |
| `-listen` | `:443` | Address to listen on |
| `-log-level` | `info` | Log level (debug, info, warn, error) |
| `-version` | | Show version information |
| `-help` | | Show help message |

## Configuration

Create a `config.yaml` file (see `config.example.yaml` for a complete example):

```yaml
# Server settings
listen: ":443"
default_port: 443

# Timeouts
connect_timeout: 10s
idle_timeout: 60s

# Logging
log_level: info

# Performance
buffer_size: 32768
max_concurrent: 10000

# Access Control (supports wildcards)
allowed_hosts:
  - "*.example.com"
  - "api.myservice.io"

denied_hosts:
  - "blocked.example.com"

# Custom routing
routes:
  - match: "*.internal.example.com"
    target: "internal-lb:443"
  - match: "api.example.com"
    target: "api-gateway:8443"
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `listen` | string | `:443` | Address and port to listen on |
| `default_port` | int | `443` | Default upstream port if not specified in route |
| `connect_timeout` | duration | `10s` | Timeout for connecting to upstream servers |
| `idle_timeout` | duration | `60s` | Idle connection timeout |
| `log_level` | string | `info` | Logging level |
| `log_file` | string | | Log file path (stdout if empty) |
| `buffer_size` | int | `32768` | Buffer size for data transfer |
| `max_concurrent` | int | `10000` | Maximum concurrent connections |
| `allowed_hosts` | []string | | Allowed hostnames (empty = allow all) |
| `denied_hosts` | []string | | Denied hostnames |
| `routes` | []Route | | Custom routing rules |

### Wildcard Patterns

Access control and routing support wildcard patterns:

- `*.example.com` - Matches any subdomain (e.g., `api.example.com`, `www.example.com`)
- `example.*` - Matches any TLD (e.g., `example.com`, `example.org`)

## Use Cases

### 1. Multi-tenant HTTPS Load Balancer

Route traffic to different backends based on hostname:

```yaml
routes:
  - match: "app1.example.com"
    target: "app1-backend:443"
  - match: "app2.example.com"
    target: "app2-backend:443"
```

### 2. Development Proxy

Forward all HTTPS traffic through a local proxy for development:

```yaml
listen: ":8443"
log_level: debug
```

### 3. Access Control Gateway

Allow only specific domains:

```yaml
allowed_hosts:
  - "*.company.com"
  - "approved-service.io"

denied_hosts:
  - "*.blocked-domain.com"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SNI Proxy                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │   Listener  │──▶│  SNI Parser  │──▶│   Access Control     │  │
│  └─────────────┘   └──────────────┘   └──────────────────────┘  │
│                                               │                  │
│                                               ▼                  │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │   Client    │◀──│    Relay     │◀──│   Route Resolver     │  │
│  └─────────────┘   └──────────────┘   └──────────────────────┘  │
│                           │                                      │
│                           ▼                                      │
│                    ┌──────────────┐                             │
│                    │   Upstream   │                             │
│                    └──────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
sniproxy/
├── cmd/
│   └── sniproxy/
│       └── main.go          # Application entry point
├── pkg/
│   ├── config/
│   │   └── config.go        # Configuration management
│   ├── proxy/
│   │   └── server.go        # Proxy server implementation
│   └── sni/
│       └── parser.go        # SNI parser for TLS ClientHello
├── config.example.yaml      # Example configuration
├── go.mod                   # Go module file
└── README.md               # This file
```

## Performance Considerations

- **Buffer Size**: Larger buffers can improve throughput for high-bandwidth connections but use more memory
- **Max Concurrent**: Set based on available file descriptors and memory
- **Idle Timeout**: Balance between connection reuse and resource consumption

## Security Notes

- This proxy does **not** decrypt TLS traffic - it only reads the unencrypted SNI extension
- The proxy cannot verify server certificates on behalf of clients
- Ensure proper firewall rules to prevent unauthorized access
- Run with minimal privileges (consider using capabilities instead of root)

## License

MIT License
