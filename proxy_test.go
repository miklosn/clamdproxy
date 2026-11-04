// Package main is used for testing the main package
package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func init() {
	// Initialize logger for tests
	logger = getLogger("error") // Use error level to minimize test output
}

func TestReadCommand(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedCmd   string
		expectedDelim byte
		expectError   bool
	}{
		{
			name:          "Null terminated command",
			input:         "PING\x00",
			expectedCmd:   "PING",
			expectedDelim: nullDelimiter,
			expectError:   false,
		},
		{
			name:          "Newline terminated command",
			input:         "VERSION\n",
			expectedCmd:   "VERSION",
			expectedDelim: newlineDelimiter,
			expectError:   false,
		},
		{
			name:          "Prefixed command",
			input:         "zVERSIONCOMMANDS\x00",
			expectedCmd:   "zVERSIONCOMMANDS",
			expectedDelim: nullDelimiter,
			expectError:   false,
		},
		{
			name:          "Empty command",
			input:         "\n",
			expectedCmd:   "",
			expectedDelim: newlineDelimiter,
			expectError:   false,
		},
		{
			name:        "Incomplete command",
			input:       "PING",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tc.input))
			cmd, delim, err := readCommand(reader)

			if tc.expectError && err == nil {
				t.Fatalf("Expected error but got none")
			}

			if !tc.expectError && err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if !tc.expectError {
				if cmd != tc.expectedCmd {
					t.Errorf("Expected command %q, got %q", tc.expectedCmd, cmd)
				}
				if delim != tc.expectedDelim {
					t.Errorf("Expected delimiter %v, got %v", tc.expectedDelim, delim)
				}
			}
		})
	}
}

func TestIsCommandAllowed(t *testing.T) {
	// Save original allowedCommands
	originalAllowed := make(map[string]bool)
	for k, v := range allowedCommands {
		originalAllowed[k] = v
	}

	// Restore after test
	defer func() {
		allowedCommands = originalAllowed
	}()

	// Set test allowed commands
	allowedCommands = map[string]bool{
		"PING":            true,
		"VERSION":         true,
		"VERSIONCOMMANDS": true,
		"INSTREAM":        true,
	}

	allowedCmds := []string{
		"PING", "VERSION", "VERSIONCOMMANDS", "INSTREAM",
		"zPING", "zVERSION", "zVERSIONCOMMANDS", "zINSTREAM",
		"nPING", "nVERSION", "nVERSIONCOMMANDS", "nINSTREAM",
	}

	disallowedCmds := []string{
		"SCAN /etc/passwd", "RELOAD", "SHUTDOWN", "CONTSCAN /etc",
		"MULTISCAN /var", "STATS", "zSTATS", "nSTATS",
		"", "UNKNOWN",
	}

	for _, cmd := range allowedCmds {
		t.Run("Allow "+cmd, func(t *testing.T) {
			if !isCommandAllowed(cmd) {
				t.Errorf("Command %q should be allowed", cmd)
			}
		})
	}

	for _, cmd := range disallowedCmds {
		t.Run("Block "+cmd, func(t *testing.T) {
			if isCommandAllowed(cmd) {
				t.Errorf("Command %q should be blocked", cmd)
			}
		})
	}
}

func TestIsConnectionClosed(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "EOF error",
			err:      io.EOF,
			expected: true,
		},
		{
			name:     "Unexpected EOF",
			err:      io.ErrUnexpectedEOF,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isConnectionClosed(tc.err)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestIsInstreamCommand(t *testing.T) {
	tests := []struct {
		cmd      string
		expected bool
	}{
		{"INSTREAM", true},
		{"zINSTREAM", true},
		{"zINSTREAM extra", true},
		{"nINSTREAM", true},
		{"PING", false},
		{"zPING", false},
		{"nVERSION", false},
	}

	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			result := isInstreamCommand(tc.cmd)
			if result != tc.expected {
				t.Errorf("For command %q, expected %v, got %v", tc.cmd, tc.expected, result)
			}
		})
	}
}

// Mock reader for testing handleInstream
// nolint:unused
type mockReader struct {
	chunks [][]byte
	index  int
}

// nolint:unused
func (m *mockReader) Read(p []byte) (n int, err error) {
	if m.index >= len(m.chunks) {
		return 0, io.EOF
	}

	n = copy(p, m.chunks[m.index])
	m.index++
	return n, nil
}

// nolint:unused
func (m *mockReader) ReadByte() (byte, error) {
	if m.index >= len(m.chunks) || len(m.chunks[m.index]) == 0 {
		return 0, io.EOF
	}

	b := m.chunks[m.index][0]
	m.chunks[m.index] = m.chunks[m.index][1:]
	if len(m.chunks[m.index]) == 0 {
		m.index++
	}
	return b, nil
}

// mockConn implements the net.Conn interface for testing
type mockConn struct{}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, io.EOF }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &mockAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &mockAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// mockAddr implements the net.Addr interface for testing
type mockAddr struct{}

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return "127.0.0.1:1234" }

func TestHandleInstream_ZeroChunk(t *testing.T) {
	// Ensure logger is initialized
	if logger == nil {
		logger = getLogger("error")
	}

	// Create a mock reader that returns a zero-size chunk
	reader := bufio.NewReader(bytes.NewReader([]byte{0, 0, 0, 0}))

	// Create a buffer to capture output
	var backendBuf bytes.Buffer

	// Create a mock proxy with all required fields
	p := &ClamdProxy{
		client:     &mockConn{}, // Add a mock connection
		backend:    &mockConn{},
		backendBuf: bufio.NewWriter(&backendBuf),
		clientBuf:  bufio.NewWriter(io.Discard), // Use io.Discard for client buffer
	}

	// Call handleInstream
	err := p.handleInstream(reader)

	// Check results
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Check that the zero chunk was forwarded
	if backendBuf.Len() != 4 {
		t.Errorf("Expected 4 bytes written, got %d", backendBuf.Len())
	}

	// Check the actual bytes
	expected := []byte{0, 0, 0, 0}
	if !bytes.Equal(backendBuf.Bytes(), expected) {
		t.Errorf("Expected %v, got %v", expected, backendBuf.Bytes())
	}
}

// readWithDeadline reads from conn until an error occurs or the deadline passes
// and returns everything received.
func readWithDeadline(t *testing.T, conn net.Conn, d time.Duration) []byte {
	t.Helper()
	// net.Pipe refuses deadlines once the peer has closed; Read then returns EOF at once.
	if err := conn.SetReadDeadline(time.Now().Add(d)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out
		}
	}
}

// A z-prefixed command terminated by a newline is framed differently by clamd,
// which reads until NUL, than by the proxy. The proxy must not enter raw INSTREAM
// forwarding in that case, otherwise the "stream data" reaches clamd as commands.
func TestFramingMismatchDoesNotForwardStreamData(t *testing.T) {
	clientSide, proxyClient := net.Pipe()
	proxyBackend, backendSide := net.Pipe()

	p := &ClamdProxy{
		client:     proxyClient,
		backend:    proxyBackend,
		backendBuf: bufio.NewWriter(proxyBackend),
		clientBuf:  bufio.NewWriter(proxyClient),
	}
	go func() {
		p.Start()
		_ = proxyClient.Close()
	}()
	go func() { _, _ = io.Copy(io.Discard, clientSide) }()

	payload := "zINSTREAM\n" + "\x00\x00\x00\x0a" + "nSHUTDOWN\n" + "\x00\x00\x00\x00"
	if _, err := clientSide.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = clientSide.Close()

	received := readWithDeadline(t, backendSide, time.Second)
	if bytes.Contains(received, []byte("SHUTDOWN")) {
		t.Fatalf("stream data reached the backend: %q", received)
	}
}

func TestParseCommand(t *testing.T) {
	tests := []struct {
		cmd    string
		prefix byte
		name   string
	}{
		{"PING", 0, "PING"},
		{"zPING", 'z', "PING"},
		{"nINSTREAM", 'n', "INSTREAM"},
		{"SCAN /etc/passwd", 0, "SCAN"},
		{"zSCAN /etc/passwd", 'z', "SCAN"},
		{"", 0, ""},
		{" zPING", 0, ""},
		{"z PING", 'z', ""},
		{"PING\t", 0, "PING\t"},
	}

	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			prefix, name := parseCommand(tc.cmd)
			if prefix != tc.prefix || name != tc.name {
				t.Errorf("parseCommand(%q) = (%q, %q), want (%q, %q)", tc.cmd, prefix, name, tc.prefix, tc.name)
			}
		})
	}
}

func TestIsFramingValid(t *testing.T) {
	tests := []struct {
		cmd      string
		delim    byte
		expected bool
	}{
		{"zPING", nullDelimiter, true},
		{"zPING", newlineDelimiter, false},
		{"nPING", newlineDelimiter, true},
		{"nPING", nullDelimiter, false},
		{"PING", newlineDelimiter, true},
		{"PING", nullDelimiter, false},
		{"zINSTREAM", nullDelimiter, true},
		{"nINSTREAM", newlineDelimiter, true},
		{"INSTREAM", newlineDelimiter, false},
		{"zINSTREAM", newlineDelimiter, false},
		{"nINSTREAM", nullDelimiter, false},
		{"", newlineDelimiter, true},
	}

	for _, tc := range tests {
		t.Run(tc.cmd+string(tc.delim), func(t *testing.T) {
			if got := isFramingValid(tc.cmd, tc.delim); got != tc.expected {
				t.Errorf("isFramingValid(%q, %q) = %v, want %v", tc.cmd, tc.delim, got, tc.expected)
			}
		})
	}
}

// startPipeProxy wires a proxy between two in-memory connections and returns the
// client-facing and backend-facing ends. The client end is closed when the proxy
// finishes, as handleConnection does.
func startPipeProxy(t *testing.T, idleTimeout time.Duration) (client, backend net.Conn, done <-chan struct{}) {
	t.Helper()
	clientSide, proxyClient := net.Pipe()
	proxyBackend, backendSide := net.Pipe()

	finished := make(chan struct{})
	go func() {
		NewClamdProxy(proxyClient, proxyBackend, idleTimeout).Start()
		_ = proxyClient.Close()
		close(finished)
	}()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = backendSide.Close()
	})
	return clientSide, backendSide, finished
}

func TestBlockedCommandClosesConnection(t *testing.T) {
	client, backend, _ := startPipeProxy(t, 0)

	go func() { _, _ = client.Write([]byte("SHUTDOWN\n")) }()

	reader := bufio.NewReader(client)
	resp, err := reader.ReadString('\n')
	if err != nil || resp != "ERROR: Command not allowed\n" {
		t.Fatalf("unexpected response %q, err %v", resp, err)
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Errorf("expected connection closed after blocked command, got %v", err)
	}
	// The proxy closes its backend end on rejection, so the peer sees EOF with no data.
	buf := make([]byte, 16)
	if n, err := backend.Read(buf); err != io.EOF || n != 0 {
		t.Errorf("backend got %q, err %v; want EOF with no data", buf[:n], err)
	}
}

func TestAllowedCommandIsForwarded(t *testing.T) {
	client, backend, _ := startPipeProxy(t, 0)

	go func() { _, _ = client.Write([]byte("zPING\x00")) }()

	buf := make([]byte, 16)
	n, err := backend.Read(buf)
	if err != nil || string(buf[:n]) != "zPING\x00" {
		t.Fatalf("backend got %q, err %v", buf[:n], err)
	}

	go func() { _, _ = backend.Write([]byte("PONG\n")) }()
	resp, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || resp != "PONG\n" {
		t.Fatalf("client got %q, err %v", resp, err)
	}
}

func TestIdleTimeoutClosesConnection(t *testing.T) {
	_, _, done := startPipeProxy(t, 50*time.Millisecond)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not close an idle client connection")
	}
}

// holdingBackend answers "PONG\n" to the first line of each connection and then
// keeps the connection open until the peer closes it, so the proxy session stays
// alive for as long as the client does.
func holdingBackend(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				r := bufio.NewReader(conn)
				if _, err := r.ReadString('\n'); err != nil {
					return
				}
				if _, err := conn.Write([]byte("PONG\n")); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, r)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func pingThroughProxy(t *testing.T, addr string) (net.Conn, string, error) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if _, err := conn.Write([]byte("PING\n")); err != nil {
		return conn, "", err
	}
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		return conn, string(buf[:n]), err
	}
	if resp := string(buf[:n]); resp != "PONG\n" {
		return conn, resp, io.ErrUnexpectedEOF
	}
	return conn, "PONG\n", nil
}

func TestServeMaxConnections(t *testing.T) {
	backendLn := holdingBackend(t)
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	savedBackend, savedMax := cli.Backend, cli.MaxConnections
	cli.Backend, cli.MaxConnections = backendLn.Addr().String(), 1
	t.Cleanup(func() {
		_ = proxyLn.Close()
		cli.Backend, cli.MaxConnections = savedBackend, savedMax
	})
	go serve(proxyLn)
	addr := proxyLn.Addr().String()

	first, resp, err := pingThroughProxy(t, addr)
	if err != nil {
		t.Fatalf("first connection should be served, got %q: %v", resp, err)
	}

	second, resp, err := pingThroughProxy(t, addr)
	_ = second.Close()
	if err == nil {
		t.Fatalf("second connection should be rejected, got %q", resp)
	}

	// Releasing the slot happens after the proxy observes the close, so retry briefly.
	_ = first.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, resp, err := pingThroughProxy(t, addr)
		_ = conn.Close()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot was not released after first client closed, last response %q", resp)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
