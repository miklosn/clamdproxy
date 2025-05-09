// Package main implements a proxy server for ClamAV's clamd daemon
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Buffer pools to reduce GC pressure
var (
	// For command reading
	cmdBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 256) // Most commands are small
			return &buf
		},
	}

	// For INSTREAM chunks
	chunkBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32*1024) // 32KB is a good balance for most virus scanning
			return &buf
		},
	}
)

// Protocol constants
const (
	nullDelimiter    = byte(0)
	newlineDelimiter = byte('\n')
)

// validClamdCommands defines all known valid clamd commands
var validClamdCommands = map[string]bool{
	"PING":            true,
	"VERSION":         true,
	"RELOAD":          true,
	"SHUTDOWN":        true,
	"SCAN":            true,
	"INSTREAM":        true,
	"FILDES":          true,
	"STATS":           true,
	"IDSESSION":       true,
	"END":             true,
	"VERSIONCOMMANDS": true,
	"MULTISCAN":       true,
	"CONTSCAN":        true,
	"ALLMATCHSCAN":    true,
}

// allowedCommands defines the commands that are permitted to be forwarded
// to the backend for security reasons
var allowedCommands = map[string]bool{
	"PING":            true,
	"INSTREAM":        true,
	"VERSION":         true,
	"VERSIONCOMMANDS": true,
	"":                true, // Allow empty commands
}

// ClamdProxy handles bidirectional proxying between client and backend clamd server.
// It filters commands to prevent unsafe operations from reaching the backend.
type ClamdProxy struct {
	client         net.Conn      // Connection to the client
	backend        net.Conn      // Connection to the backend clamd server
	backendBuf     *bufio.Writer // Buffered writer for backend
	clientBuf      *bufio.Writer // Buffered writer for client
	lastStreamSize int64         // Size of the last streamed file
}

// NewClamdProxy creates a new proxy instance with the given client and backend connections
func NewClamdProxy(client, backend net.Conn) *ClamdProxy {
	return &ClamdProxy{
		client:     client,
		backend:    backend,
		backendBuf: bufio.NewWriterSize(backend, 64*1024), // 64KB buffer
		clientBuf:  bufio.NewWriterSize(client, 64*1024),  // 64KB buffer
	}
}

// Start begins bidirectional proxying between client and backend.
// It launches a goroutine to handle client->backend traffic and
// directly processes backend->client traffic in the current goroutine.
func (p *ClamdProxy) Start() {
	clientAddr := p.client.RemoteAddr()
	logger.Info("Starting proxy", "client", clientAddr)

	// Handle client -> backend in a separate goroutine
	go p.handleClientToBackend()

	// Handle backend -> client in the current goroutine
	// Use buffered copy instead of direct io.Copy
	buf := make([]byte, 64*1024) // 64KB buffer
	bytesWritten := int64(0)
	var err error

	// Buffer to accumulate response for parsing
	responseBuf := make([]byte, 0, 1024)

	for {
		nr, er := p.backend.Read(buf)
		if nr > 0 {
			// Add to response buffer for parsing
			responseBuf = append(responseBuf, buf[:nr]...)

			// Log the raw response for debugging
			logger.Debug("Received response from backend",
				"bytes", nr,
				"preview", truncateString(string(buf[:nr]), 100))

			// Check for virus detection in the response
			p.parseResponseForVirus(responseBuf)

			// Clear the response buffer if it gets too large or contains a complete response
			if len(responseBuf) > 4096 || strings.Contains(string(responseBuf), "\n") {
				responseBuf = make([]byte, 0, 1024)
			}

			nw, ew := p.clientBuf.Write(buf[0:nr])
			if nw > 0 {
				bytesWritten += int64(nw)
			}
			if ew != nil {
				logger.Debug("Error writing to client buffer", "error", ew)
				err = ew
				break
			}
			if nr != nw {
				logger.Debug("Short write to client buffer", "expected", nr, "written", nw)
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				logger.Debug("Error reading from backend", "error", er)
				err = er
			}
			break
		}

		// Flush the buffer periodically to avoid delays
		if p.clientBuf.Buffered() > 32*1024 {
			if err := p.clientBuf.Flush(); err != nil {
				logger.Debug("Error flushing buffer to client", "error", err)
			}
		}
	}

	// Final flush
	if err := p.clientBuf.Flush(); err != nil {
		logger.Debug("Error flushing final buffer to client", "error", err)
	}

	if err != nil {
		if isConnectionClosed(err) {
			logger.Debug("Backend connection closed", "client", clientAddr, "error", err)
		} else {
			logger.Debug("Error copying from backend to client", "client", clientAddr, "error", err)
		}
	} else {
		logger.Info("Proxy completed", "client", clientAddr, "bytesTransferred", bytesWritten)
	}
}

// handleClientToBackend processes commands from client to backend,
// filtering out disallowed commands and handling special protocol cases.
func (p *ClamdProxy) handleClientToBackend() {
	reader := bufio.NewReader(p.client)
	clientAddr := p.client.RemoteAddr()

	for {
		// Try to read a command
		cmd, delim, err := readCommand(reader)
		if err != nil {
			if err == io.EOF {
				// Normal client disconnection, log at debug level
				logger.Info("Client disconnected", "client", clientAddr)
			} else {
				// Only log as error if it's not a connection reset or broken pipe
				if isConnectionClosed(err) {
					logger.Debug("Client connection closed", "client", clientAddr, "error", err)
				} else {
					logger.Debug("Error reading command", "client", clientAddr, "error", err)
					// Record command error in metrics
					if proxyMetrics != nil {
						proxyMetrics.RecordCommandError("unknown", err.Error())
					}
				}
			}
			// Close the backend connection to signal we're done
			if err := p.backend.Close(); err != nil {
				logger.Debug("Error closing backend connection", "error", err)
			}
			break
		}

		// Skip empty commands
		if cmd == "" {
			continue
		}

		// Only log commands at appropriate levels
		logger.Debug("Command received", "client", clientAddr, "command", cmd)

		// Check if command is allowed and record start time
		allowed := isCommandAllowed(cmd)
		commandStart := time.Now()

		// Record command metrics
		if proxyMetrics != nil {
			proxyMetrics.RecordCommand(cmd, allowed)
		}

		if allowed {
			// Forward the command to backend using buffered writer
			if _, err := p.backendBuf.Write(append([]byte(cmd), delim)); err != nil {
				logger.Debug("Error forwarding command", "error", err)
				// Record command error in metrics
				if proxyMetrics != nil {
					proxyMetrics.RecordCommandError(cmd, err.Error())
				}
				break
			}
			// Flush after each command to ensure it's sent immediately
			if err := p.backendBuf.Flush(); err != nil {
				logger.Debug("Error flushing command", "error", err)
				break
			}

			// Record command duration
			if proxyMetrics != nil && !isInstreamCommand(cmd) {
				proxyMetrics.RecordCommandDuration(cmd, time.Since(commandStart))
			}

			// Handle special case for INSTREAM command (file streaming)
			if isInstreamCommand(cmd) {
				logger.Debug("Processing INSTREAM data", "client", clientAddr)

				instreamStart := time.Now()
				if err := p.handleInstream(reader); err != nil {
					logger.Debug("Error handling INSTREAM data",
						"client", clientAddr,
						"error", err)
					// Record command error in metrics
					if proxyMetrics != nil {
						proxyMetrics.RecordCommandError(cmd, err.Error())
					}
					break
				}

				// Record INSTREAM command duration after completion
				if proxyMetrics != nil {
					proxyMetrics.RecordCommandDuration(cmd, time.Since(instreamStart))
				}
			}
		} else {
			logger.Debug("Blocked command", "client", clientAddr, "command", cmd) // Changed from Info to Debug
			// Send error response to client using buffered writer
			response := "ERROR: Command not allowed\n"
			if _, err := p.clientBuf.WriteString(response); err != nil {
				logger.Debug("Error sending error response", "error", err)
				break
			}

			// Record command duration for blocked commands too
			if proxyMetrics != nil {
				proxyMetrics.RecordCommandDuration(cmd, time.Since(commandStart))
			}
			if err := p.clientBuf.Flush(); err != nil {
				logger.Debug("Error flushing error response", "error", err)
				break
			}
		}
	}
}

// isInstreamCommand determines if a command is an INSTREAM command
// which requires special handling for the data stream that follows.
func isInstreamCommand(cmd string) bool {
	return (strings.HasPrefix(cmd, "z") && strings.HasSuffix(cmd, "INSTREAM")) ||
		(strings.HasPrefix(cmd, "n") && strings.HasSuffix(cmd, "INSTREAM"))
}

// readCommand reads a command from the reader, handling both null and newline delimiters.
// Returns the command string, the delimiter that terminated it, and any error encountered.
func readCommand(reader *bufio.Reader) (string, byte, error) {
	// Get buffer from pool
	bufPtr := cmdBufPool.Get().(*[]byte)
	cmdBytes := (*bufPtr)[:0] // Reset length but keep capacity

	var delim byte

	// Read until null or newline
	for {
		b, err := reader.ReadByte()
		if err != nil {
			cmdBufPool.Put(bufPtr) // Return buffer to pool on error
			return "", 0, err
		}

		if b == nullDelimiter || b == newlineDelimiter {
			delim = b
			break
		}

		cmdBytes = append(cmdBytes, b)
		*bufPtr = cmdBytes // Update the pointer
	}

	// Copy to string before returning buffer to pool
	cmd := string(cmdBytes)
	cmdBufPool.Put(bufPtr)

	return cmd, delim, nil
}

// isCommandAllowed checks if a command is allowed to be forwarded to the backend.
// It extracts the actual command name, handling protocol prefixes, and checks
// against the allowedCommands whitelist.
func isCommandAllowed(cmd string) bool {
	// Extract the actual command from the prefix
	cmdParts := strings.Fields(cmd)
	if len(cmdParts) == 0 {
		return false // Empty commands are not allowed
	}

	// Handle commands with z/n prefix (protocol variations)
	actualCmd := cmdParts[0]
	if strings.HasPrefix(actualCmd, "z") || strings.HasPrefix(actualCmd, "n") {
		actualCmd = actualCmd[1:]
	}

	// Check if command is in allowed list
	return allowedCommands[actualCmd]
}

// isConnectionClosed checks if an error indicates that the connection was closed by the client
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific network error types
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Only check for timeout errors, not temporary (which is deprecated)
		if netErr.Timeout() {
			return false
		}
	}

	// Check for specific syscall errors that indicate closed connections
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	// Check for EOF which indicates clean connection close
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)
}

// handleInstream handles the special INSTREAM command data forwarding.
// INSTREAM protocol: 4-byte size header followed by chunk data, repeating until a zero-size chunk.
func (p *ClamdProxy) handleInstream(reader *bufio.Reader) error {
	clientAddr := p.client.RemoteAddr()
	totalBytes := 0
	chunks := 0

	// Size buffer is small and frequently reused, so we'll keep it local
	sizeBytes := make([]byte, 4)

	for {
		// Read chunk size (4 bytes in network byte order)
		if _, err := io.ReadFull(reader, sizeBytes); err != nil {
			return fmt.Errorf("failed to read chunk size: %w", err)
		}

		// Forward size bytes to backend using buffered writer
		if _, err := p.backendBuf.Write(sizeBytes); err != nil {
			return fmt.Errorf("failed to forward chunk size: %w", err)
		}

		// Calculate chunk size (big-endian)
		size := int(sizeBytes[0])<<24 | int(sizeBytes[1])<<16 | int(sizeBytes[2])<<8 | int(sizeBytes[3])

		// If size is 0, we're done with the stream
		if size == 0 {
			logger.Debug("INSTREAM completed",
				"client", clientAddr,
				"totalBytes", totalBytes,
				"chunks", chunks)
			break
		}

		// Handle the chunk data
		if size <= 32*1024 { // If it fits in our pooled buffer size
			// Get a buffer from the pool
			chunkPtr := chunkBufPool.Get().(*[]byte)
			chunk := *chunkPtr

			// Read chunk data into the buffer
			if _, err := io.ReadFull(reader, chunk[:size]); err != nil {
				chunkBufPool.Put(chunkPtr) // Return buffer to pool on error
				return fmt.Errorf("failed to read chunk data: %w", err)
			}

			// Forward chunk data using buffered writer
			if _, err := p.backendBuf.Write(chunk[:size]); err != nil {
				chunkBufPool.Put(chunkPtr) // Return buffer to pool on error
				return fmt.Errorf("failed to forward chunk data: %w", err)
			}

			// Return buffer to pool immediately after use
			chunkBufPool.Put(chunkPtr)
		} else {
			// For unusually large chunks, copy to buffered writer
			if _, err := io.CopyN(p.backendBuf, reader, int64(size)); err != nil {
				return fmt.Errorf("failed to copy chunk data: %w", err)
			}
		}

		totalBytes += size
		chunks++
	}

	// After the INSTREAM command completes successfully, store the final file size
	p.lastStreamSize = int64(totalBytes)

	// Flush the backend buffer to ensure all data is sent
	if err := p.backendBuf.Flush(); err != nil {
		return fmt.Errorf("failed to flush backend buffer: %w", err)
	}

	return nil
}

// parseResponseForVirus checks if the response contains virus detection information
// and records metrics if a virus is found
func (p *ClamdProxy) parseResponseForVirus(response []byte) {
	// Convert to string for easier parsing
	respStr := string(response)

	// Add debug logging to see what's in the response
	logger.Debug("Parsing response", "length", len(respStr), "preview", truncateString(respStr, 100))

	// Check if this is an INSTREAM response (either clean or with virus)
	if strings.Contains(respStr, "stream") {
		// Default to clean file (no virus)
		virusFound := false
		virusName := ""
		filename := "stream"

		// Check for virus detection
		if strings.Contains(respStr, " FOUND") {
			logger.Debug("Found virus detection pattern in response")
			lines := strings.Split(respStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, " FOUND") {
					logger.Debug("Processing virus line", "line", line)
					parts := strings.Split(line, ": ")
					if len(parts) >= 2 {
						fileInfo := parts[0]
						detectionInfo := strings.TrimSuffix(parts[1], " FOUND")

						// Extract filename from fileInfo
						// Format: "instream(172.18.0.5@35478)"
						filename = fileInfo
						if strings.Contains(fileInfo, "(") && strings.Contains(fileInfo, ")") {
							// Extract the part between parentheses
							start := strings.Index(fileInfo, "(") + 1
							end := strings.Index(fileInfo, ")")
							if start > 0 && end > start {
								clientInfo := fileInfo[start:end]
								// Use client info as part of the filename
								filename = fileInfo[:start-1] + "_" + clientInfo
							}
						}

						virusFound = true
						virusName = detectionInfo

						logger.Info("Virus detected",
							"file", filename,
							"virus", detectionInfo,
							"size", p.lastStreamSize)
					}
				}
			}
		} else if strings.Contains(respStr, "OK") {
			// This is a clean file
			logger.Debug("Clean file detected", "size", p.lastStreamSize)
		}

		// Record metrics for all scanned files, whether clean or infected
		if proxyMetrics != nil {
			// Use the actual file size if available
			fileSize := p.lastStreamSize
			if fileSize == 0 {
				fileSize = int64(1024) // Default 1KB if size unknown
			}

			proxyMetrics.RecordFileScan(filename, fileSize, virusFound, virusName)

			if virusFound {
				logger.Debug("Recorded virus metrics",
					"file", filename,
					"size", fileSize,
					"virus", virusName)
			} else {
				logger.Debug("Recorded clean file metrics",
					"file", filename,
					"size", fileSize)
			}
		}
	}
}

// Helper function to truncate long strings for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
