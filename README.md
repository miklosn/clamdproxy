# clamdproxy

[![Go Report Card](https://goreportcard.com/badge/github.com/miklosn/clamdproxy)](https://goreportcard.com/report/github.com/miklosn/clamdproxy)
[![GoDoc](https://pkg.go.dev/badge/github.com/miklosn/clamdproxy)](https://pkg.go.dev/github.com/miklosn/clamdproxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/release/miklosn/clamdproxy.svg)](https://github.com/miklosn/clamdproxy/releases/latest)

A Go proxy for clamd that filters out insecure commands.

## Project Goals

While ClamAV's protocol was not originally designed for remote scanning, there are legitimate reasons to do so in certain environments. clamdproxy enables remote virus scanning by acting as a security layer between clients and the ClamAV daemon.

Common use cases include:

- Providing virus scanning services to containerized applications without installing ClamAV in each container
- Creating centralized scanning services in microservice architectures
- Enabling scanning from untrusted networks without exposing full clamd functionality
- Integrating with API gateways and service meshes for content security

## Features

- Proxies clamd protocol commands to a backend clamd server
- Uses a whitelist approach
- Blocks all other commands for enhanced security
- Supports both null character and newline delimited commands
- Handles special INSTREAM command properly
- Performance optimized with buffer pools and efficient I/O
- Configurable logging levels

## Installation

### Using Pre-built Binaries

The easiest way to get started is to download a pre-built binary from the [GitHub Releases](https://github.com/yourusername/clamdproxy/releases) page:

1. Navigate to the latest release
2. Download the appropriate binary for your platform (Linux, macOS, Windows)
3. Make the file executable (on Unix-based systems):

   ```
   chmod +x clamdproxy
   ```

4. Move it to a directory in your PATH (optional):

   ```
   sudo mv clamdproxy /usr/local/bin/
   ```

### Building from Source

If you prefer to build from source:

```
git clone https://github.com/yourusername/clamdproxy.git
cd clamdproxy
go build -o clamdproxy
```

## Usage

Basic usage:

```
clamdproxy --listen 127.0.0.1:3310 --backend 127.0.0.1:3311
```

### Options

- `--listen`: Address to listen on (default: 127.0.0.1:3310)
- `--backend`: Address of the backend clamd server (default: 127.0.0.1:3311)
- `--log-level`: Logging level: debug, info, warn, error (default: warn)
- `--pprof`: Address for pprof HTTP server (disabled if empty)

## Protocol

The proxy supports the clamd protocol as described in the clamd documentation. It handles both null-terminated commands (prefixed with 'z') and newline-terminated commands (prefixed with 'n').

## Performance

clamdproxy is designed to be lightweight and efficient:

- Uses buffer pools to reduce memory allocations
- Implements efficient I/O with buffered readers/writers
- Minimal overhead for proxying commands and data

## Project status

I use this program in production with quite some traffic, albeit in a very narrow use case. Ideas, bug reports, contributions are welcome!
