// Package main implements a proxy server for ClamAV's clamd daemon
// that filters unsafe commands and forwards safe ones to the backend.
package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" // Register pprof handlers
	"os"
	"strings"

	"github.com/alecthomas/kong"
)

// CLI configuration structure for Kong
var cli struct {
	Listen          string   `name:"listen" help:"Address to listen on" default:"127.0.0.1:3310"`
	Backend         string   `name:"backend" help:"Address of the backend clamd server" default:"127.0.0.1:3311"`
	LogLevel        string   `name:"log-level" help:"Log level (debug, info, warn, error)" default:"warn" enum:"debug,info,warn,error"`
	PprofAddr       string   `name:"pprof" help:"Address for pprof HTTP server (disabled if empty)" default:""`
	AllowedCommands []string `name:"allow-command" help:"ClamAV commands to allow (can be specified multiple times)"`
}

// Global logger used throughout the code
var logger *slog.Logger

// getLogger creates and returns a logger with the specified log level
func getLogger(logLevel string) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelWarn
	}

	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	return slog.New(logHandler)
}

func main() {
	// Parse command line arguments with Kong
	ctx := kong.Parse(&cli)
	_ = ctx // You can use ctx for subcommands if needed in the future

	// Configure logger with parsed arguments
	logger = getLogger(cli.LogLevel)
	slog.SetDefault(logger)

	// Initialize allowed commands
	initAllowedCommands()

	logger.Warn("Starting clamdproxy",
		"listen", cli.Listen,
		"backend", cli.Backend)

	// Start pprof server if enabled
	if cli.PprofAddr != "" {
		go func() {
			logger.Warn("Starting pprof server",
				"addr", cli.PprofAddr,
				"url", fmt.Sprintf("http://%s/debug/pprof/", cli.PprofAddr))
			if err := http.ListenAndServe(cli.PprofAddr, nil); err != nil {
				logger.Error("Failed to start pprof server", "error", err)
			}
		}()
	}

	listener, err := net.Listen("tcp", cli.Listen)
	if err != nil {
		logger.Error("Failed to listen", "addr", cli.Listen, "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			logger.Error("Failed to close listener", "error", err)
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Error accepting connection", "error", err)
			continue
		}
		go handleConnection(conn)
	}
}

// handleConnection manages a client connection by establishing a backend connection
// and setting up bidirectional proxying between them
func handleConnection(clientConn net.Conn) {
	defer func() {
		if err := clientConn.Close(); err != nil {
			logger.Error("Failed to close client connection", "error", err)
		}
	}()
	clientAddr := clientConn.RemoteAddr()

	logger.Info("Connection established", "client", clientAddr)

	backendConn, err := net.Dial("tcp", cli.Backend)
	if err != nil {
		logger.Error("Failed to connect to backend",
			"backend", &cli.Backend,
			"client", &clientAddr,
			"error", err)
		return
	}
	defer func() {
		if err := backendConn.Close(); err != nil {
			logger.Debug("Failed to close backend connection", "error", err)
		}
	}()

	logger.Info("Connected to backend", "backend", cli.Backend, "client", clientAddr)

	proxy := NewClamdProxy(clientConn, backendConn)
	proxy.Start()

	logger.Info("Connection closed", "client", clientAddr)
}

// initAllowedCommands initializes the allowedCommands map based on CLI options
func initAllowedCommands() {
	// If no commands specified, use the default set
	if len(cli.AllowedCommands) == 0 {
		// Default commands are already set in the allowedCommands variable
		logger.Info("Using default allowed commands", "commands", allowedCommands)
		return
	}

	// Clear the current allowed commands
	for cmd := range allowedCommands {
		delete(allowedCommands, cmd)
	}

	// Add each specified command if it's valid
	for _, cmd := range cli.AllowedCommands {
		cmd = strings.ToUpper(cmd) // Normalize to uppercase
		if validClamdCommands[cmd] {
			allowedCommands[cmd] = true
		} else {
			logger.Warn("Ignoring invalid command", "command", cmd)
		}
	}

	// Log the final set of allowed commands
	var cmdList []string
	for cmd := range allowedCommands {
		cmdList = append(cmdList, cmd)
	}
	logger.Info("Configured allowed commands", "commands", cmdList)
}
