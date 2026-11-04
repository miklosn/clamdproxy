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
}

// ClamdProxy handles bidirectional proxying between client and backend clamd server.
// It filters commands to prevent unsafe operations from reaching the backend.
type ClamdProxy struct {
	client     net.Conn      // Connection to the client
	backend    net.Conn      // Connection to the backend clamd server
	backendBuf *bufio.Writer // Buffered writer for backend
	clientBuf  *bufio.Writer // Buffered writer for client
}

// idleConn refreshes the connection deadline before every read and write so that
// idle peers are disconnected while slow but active transfers are not.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// NewClamdProxy creates a new proxy instance with the given client and backend connections.
// A non-zero idleTimeout closes the client connection when no data is read from or
// written to it for that long.
func NewClamdProxy(client, backend net.Conn, idleTimeout time.Duration) *ClamdProxy {
	if idleTimeout > 0 {
		client = &idleConn{Conn: client, timeout: idleTimeout}
	}
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

	for {
		nr, er := p.backend.Read(buf)
		if nr > 0 {
			nw, ew := p.clientBuf.Write(buf[0:nr])
			if nw > 0 {
				bytesWritten += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}

		// Backend responses are small and complete per read, so flush each one
		// to the client immediately instead of waiting for the connection to end.
		if err := p.clientBuf.Flush(); err != nil {
			logger.Debug("Error flushing buffer to client", "error", err)
			break
		}
	}

	// Final flush
	if err := p.clientBuf.Flush(); err != nil {
		logger.Debug("Error flushing final buffer to client", "error", err)
	}

	if err != nil {
		if isConnectionClosed(err) {
			logger.Debug("Backend connection closed",
				"client", clientAddr,
				"error", err)
		} else {
			logger.Debug("Error copying from backend to client",
				"client", clientAddr,
				"error", err)
		}
	} else {
		logger.Info("Proxy completed",
			"client", clientAddr,
			"bytesTransferred", bytesWritten)
	}
}

// handleClientToBackend processes commands from client to backend,
// filtering out disallowed commands and handling special protocol cases.
func (p *ClamdProxy) handleClientToBackend() {
	reader := bufio.NewReader(p.client)
	clientAddr := p.client.RemoteAddr()

	// Closing the backend on every exit path unblocks the backend->client copy in
	// Start, so the session ends as soon as the client side is done.
	defer func() {
		if err := p.backend.Close(); err != nil {
			logger.Debug("Error closing backend connection", "error", err)
		}
	}()

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
				}
			}
			break
		}

		// Only log commands at appropriate levels
		logger.Debug("Command received", "client", clientAddr, "command", cmd)

		// A command whose delimiter does not match its prefix would be framed
		// differently by clamd than by this proxy, so it is rejected before the
		// allowlist check. Any rejection ends the session, as clamd itself does
		// after a single command outside IDSESSION.
		if !isFramingValid(cmd, delim) {
			logger.Info("Blocked command", "client", clientAddr, "command", cmd, "reason", "invalid framing")
			p.sendError()
			break
		}
		if !isCommandAllowed(cmd) {
			logger.Info("Blocked command", "client", clientAddr, "command", cmd, "reason", "not allowed")
			p.sendError()
			break
		}

		// Forward the command to backend using buffered writer
		if _, err := p.backendBuf.Write(append([]byte(cmd), delim)); err != nil {
			logger.Debug("Error forwarding command", "error", err)
			break
		}
		// Flush after each command to ensure it's sent immediately
		if err := p.backendBuf.Flush(); err != nil {
			logger.Debug("Error flushing command", "error", err)
			break
		}

		// Handle special case for INSTREAM command (file streaming)
		if isInstreamCommand(cmd) {
			logger.Debug("Processing INSTREAM data", "client", clientAddr)

			if err := p.handleInstream(reader); err != nil {
				logger.Debug("Error handling INSTREAM data",
					"client", clientAddr,
					"error", err)
				break
			}
		}
	}
}

// sendError sends the rejection response to the client.
func (p *ClamdProxy) sendError() {
	if _, err := p.clientBuf.WriteString("ERROR: Command not allowed\n"); err != nil {
		logger.Debug("Error sending error response", "error", err)
		return
	}
	if err := p.clientBuf.Flush(); err != nil {
		logger.Debug("Error flushing error response", "error", err)
	}
}

// parseCommand splits a raw command into its optional z/n prefix and the command
// name. The prefix must be the very first byte, as clamd requires, and the name
// ends at the first space so that arguments are ignored.
func parseCommand(cmd string) (prefix byte, name string) {
	if len(cmd) > 0 && (cmd[0] == 'z' || cmd[0] == 'n') {
		prefix = cmd[0]
		cmd = cmd[1:]
	}
	name, _, _ = strings.Cut(cmd, " ")
	return prefix, name
}

// isFramingValid reports whether the delimiter that terminated a command matches
// what clamd expects for its prefix: NUL for 'z', newline for 'n', and newline for
// old-style unprefixed commands. Unprefixed INSTREAM is rejected because clamd
// requires a prefix for it and the proxy could not frame the data stream reliably.
func isFramingValid(cmd string, delim byte) bool {
	prefix, name := parseCommand(cmd)
	switch prefix {
	case 'z':
		return delim == nullDelimiter
	case 'n':
		return delim == newlineDelimiter
	default:
		return delim == newlineDelimiter && name != "INSTREAM"
	}
}

// isInstreamCommand determines if a command is an INSTREAM command
// which requires special handling for the data stream that follows.
func isInstreamCommand(cmd string) bool {
	_, name := parseCommand(cmd)
	return name == "INSTREAM"
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
	_, name := parseCommand(cmd)
	return allowedCommands[name]
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

		// Only log chunk details at the most verbose level and only occasionally
		if chunks%100 == 0 {
			logger.Debug("INSTREAM progress",
				"client", clientAddr,
				"chunks", chunks,
				"totalBytes", totalBytes)
		}

		// Flush periodically to balance between batching and responsiveness
		if chunks%10 == 0 {
			if err := p.backendBuf.Flush(); err != nil {
				return fmt.Errorf("failed to flush data: %w", err)
			}
		}
	}

	// Final flush to ensure all data is sent
	if err := p.backendBuf.Flush(); err != nil {
		return fmt.Errorf("failed to flush final data: %w", err)
	}

	return nil
}
