// Package main is used for testing the main package
package main

import (
	"bufio"
	"bytes"
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
		{"INSTREAM", false},
		{"zINSTREAM", true},
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
