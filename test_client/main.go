// Package main implements a test client for clamdproxy
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

var (
	proxyAddr string
	timeout   int
)

func init() {
	flag.StringVar(&proxyAddr, "proxy", "127.0.0.1:3310", "Address of the clamdproxy server")
	flag.IntVar(&timeout, "timeout", 5, "Timeout in seconds for command responses")
	flag.Parse()
}

// Commands to test, grouped by expected behavior
var (
	// Commands that should be allowed (matching proxy's allowedCommands)
	allowedCommands = []string{
		"PING", "VERSION", "VERSIONCOMMANDS",
		"nPING", "nVERSION", "nVERSIONCOMMANDS",
		"zPING", "zVERSION", "zVERSIONCOMMANDS",
		"INSTREAM", "nINSTREAM", "zINSTREAM",
	}

	// Commands that should be blocked
	disallowedCommands = []string{
		"RELOAD", "SHUTDOWN", "",
		"SCAN /etc/passwd", "CONTSCAN /etc", "MULTISCAN /var",
		"STATS", "nSTATS", "zSTATS",
		"ALLMATCHSCAN /etc", "FILDES", "nFILDES",
	}

	// EICAR test string (safe virus test pattern)
	eicarString = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
)

func main() {
	fmt.Printf("Testing clamdproxy at %s (timeout: %ds)\n\n", proxyAddr, timeout)

	// Create a tabwriter for formatted output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Print table headers
	if _, err := fmt.Fprintln(w, "Command\tStatus\tResponse"); err != nil {
		fmt.Printf("Error writing to output: %v\n", err)
		return
	}
	if _, err := fmt.Fprintln(w, "-------\t------\t--------"); err != nil {
		fmt.Printf("Error writing to output: %v\n", err)
		return
	}

	// Test allowed commands
	if _, err := fmt.Fprintln(w, "=== Allowed Commands ===\t\t"); err != nil {
		fmt.Printf("Error writing to output: %v\n", err)
		return
	}
	for _, cmd := range allowedCommands {
		// Skip INSTREAM commands for now, we'll test them separately
		if strings.Contains(cmd, "INSTREAM") {
			continue
		}
		status, response := testCommand(cmd)
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", cmd, status, formatResponse(response)); err != nil {
			fmt.Printf("Error writing to output: %v\n", err)
			return
		}
	}

	if _, err := fmt.Fprintln(w, "\n=== Blocked Commands ===\t\t"); err != nil {
		fmt.Printf("Error writing to output: %v\n", err)
		return
	}
	for _, cmd := range disallowedCommands {
		status, response := testCommand(cmd)
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", cmd, status, formatResponse(response)); err != nil {
			fmt.Printf("Error writing to output: %v\n", err)
			return
		}
	}

	if _, err := fmt.Fprintln(w, "\n=== Special Commands ===\t\t"); err != nil {
		fmt.Printf("Error writing to output: %v\n", err)
		return
	}
	status, response := testInstream()
	if _, err := fmt.Fprintf(w, "INSTREAM (EICAR test)\t%s\t%s\n", status, formatResponse(response)); err != nil {
		fmt.Printf("Error writing to output: %v\n", err)
		return
	}

	// Add a connection test
	if _, err := fmt.Fprintln(w, "\n=== Connection Test ===\t\t"); err != nil {
		fmt.Printf("Error writing to output: %v\n", err)
		return
	}
	if isBackendReachable() {
		if _, err := fmt.Fprintln(w, "Backend connection\tOK\tBackend server is reachable"); err != nil {
			fmt.Printf("Error writing to output: %v\n", err)
			return
		}
	} else {
		if _, err := fmt.Fprintln(w, "Backend connection\tFAIL\tCannot reach backend server"); err != nil {
			fmt.Printf("Error writing to output: %v\n", err)
			return
		}
	}

	// Flush the tabwriter
	if err := w.Flush(); err != nil {
		fmt.Printf("Error flushing output: %v\n", err)
	}
}

// testCommand sends a command to the proxy and returns the status and response
func testCommand(cmd string) (string, string) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return "ERROR", fmt.Sprintf("Connection failed: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("Error closing connection: %v\n", err)
		}
	}()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return "ERROR", fmt.Sprintf("Failed to set deadline: %v", err)
	}

	// Determine the appropriate terminator based on command prefix
	var fullCmd string
	if strings.HasPrefix(cmd, "z") {
		fullCmd = cmd + string(byte(0)) // null terminator for z-prefixed commands
	} else if strings.HasPrefix(cmd, "n") {
		fullCmd = cmd + "\n" // newline terminator for n-prefixed commands
	} else {
		// Default to newline terminator for commands without prefix
		fullCmd = cmd + "\n"
	}

	_, err = conn.Write([]byte(fullCmd))
	if err != nil {
		return "ERROR", fmt.Sprintf("Send failed: %v", err)
	}

	// Read response with timeout
	buffer := make([]byte, 4096) // Larger buffer for potentially larger responses
	
	// Set a read deadline
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return "ERROR", fmt.Sprintf("Failed to set deadline: %v", err)
	}
	
	n, err := conn.Read(buffer)
	if err != nil {
		if err == io.EOF {
			return "CLOSED", "Connection closed by server"
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "TIMEOUT", "Response timeout"
		} else {
			return "ERROR", fmt.Sprintf("Read failed: %v", err)
		}
	}

	response := string(buffer[:n])
	
	// Check for error responses
	if strings.HasPrefix(response, "ERROR") {
		return "BLOCKED", response
	}
	
	return "OK", response
}

// testInstream tests the INSTREAM command with an EICAR test file
func testInstream() (string, string) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return "ERROR", fmt.Sprintf("Connection failed: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("Error closing connection: %v\n", err)
		}
	}()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return "ERROR", fmt.Sprintf("Failed to set deadline: %v", err)
	}

	// Send INSTREAM command (using newline terminator)
	_, err = conn.Write([]byte("nINSTREAM\n"))
	if err != nil {
		return "ERROR", fmt.Sprintf("Send failed: %v", err)
	}

	// Send EICAR test string as a chunk
	var sizeBuf [4]byte
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(eicarString)))

	// Send size
	_, err = conn.Write(sizeBuf[:])
	if err != nil {
		return "ERROR", fmt.Sprintf("Send chunk size failed: %v", err)
	}

	// Send data
	_, err = conn.Write(eicarString)
	if err != nil {
		return "ERROR", fmt.Sprintf("Send chunk data failed: %v", err)
	}

	// Send zero-length chunk to terminate stream
	_, err = conn.Write([]byte{0, 0, 0, 0})
	if err != nil {
		return "ERROR", fmt.Sprintf("Send terminating chunk failed: %v", err)
	}

	// Read response with a larger buffer for potentially larger virus detection responses
	buffer := make([]byte, 4096)
	
	// Set a read deadline
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
		return "ERROR", fmt.Sprintf("Failed to set deadline: %v", err)
	}
	
	n, err := conn.Read(buffer)
	if err != nil {
		if err == io.EOF {
			return "CLOSED", "Connection closed by server"
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "TIMEOUT", "Response timeout"
		} else {
			return "ERROR", fmt.Sprintf("Read failed: %v", err)
		}
	}

	response := string(buffer[:n])
	
	// Check if the response contains a virus detection
	if strings.Contains(response, "FOUND") {
		return "VIRUS", response
	}
	
	return "OK", response
}

// formatResponse formats the response for display in the table
// It handles multiline responses by replacing newlines with a special marker
// and wraps long lines instead of truncating them
func formatResponse(response string) string {
	// Replace newlines with a visible marker for clarity in the table
	response = strings.TrimSpace(response)
	response = strings.ReplaceAll(response, "\n", " ↵ ")

	// Wrap long responses instead of truncating them
	if len(response) > 80 {
		var wrapped strings.Builder
		remaining := response

		for len(remaining) > 0 {
			lineEnd := 80
			if len(remaining) < lineEnd {
				lineEnd = len(remaining)
			}

			if wrapped.Len() > 0 {
				wrapped.WriteString("\n\t\t") // Indent continuation lines
			}

			wrapped.WriteString(remaining[:lineEnd])
			remaining = remaining[lineEnd:]
		}

		return wrapped.String()
	}

	return response
}
// isBackendReachable checks if the proxy server is reachable
func isBackendReachable() bool {
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Duration(timeout)*time.Second)
	if err != nil {
		return false
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("Error closing connection: %v\n", err)
		}
	}()
	return true
}
