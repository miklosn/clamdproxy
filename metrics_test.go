package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	// Initialize metrics with a test server
	metrics, err := InitMetrics("localhost:0")
	require.NoError(t, err)
	require.NotNil(t, metrics)
	defer func() {
		err := metrics.Close()
		require.NoError(t, err)
	}()

	t.Run("RecordConnection", func(t *testing.T) {
		metrics.RecordConnection("127.0.0.1:1234")
		resp := getMetrics(t, metrics)
		
		// Check for the counter without the client label
		assert.Contains(t, resp, "clamdproxy_connections_total")
		
		// Check for active connections
		assert.Contains(t, resp, "clamdproxy_active_connections")
	})

	t.Run("RecordConnectionClosed", func(t *testing.T) {
		metrics.RecordConnection("127.0.0.1:1234")
		metrics.RecordConnectionClosed()
		resp := getMetrics(t, metrics)
		assert.Contains(t, resp, `clamdproxy_active_connections`)
	})

	t.Run("RecordCommand", func(t *testing.T) {
		metrics.RecordCommand("PING", true)
		resp := getMetrics(t, metrics)
		assert.Contains(t, resp, `clamdproxy_commands_total{allowed="true",command="PING",otel_scope_name="clamdproxy"`)
	})

	t.Run("RecordCommandError", func(t *testing.T) {
		metrics.RecordCommandError("SCAN", "connection refused")
		resp := getMetrics(t, metrics)
		assert.Contains(t, resp, `clamdproxy_command_errors_total{command="SCAN",error="connection refused",otel_scope_name="clamdproxy"`)
	})
}

// Helper function to get metrics from the HTTP endpoint
func getMetrics(t *testing.T, m *Metrics) string {
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.metricServer.Handler.ServeHTTP(w, r)
	})

	handler.ServeHTTP(w, req)
	resp := w.Result()
	defer func() {
		err := resp.Body.Close()
		require.NoError(t, err)
	}()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
	}

	body := new(strings.Builder)
	_, err := io.Copy(body, resp.Body)
	require.NoError(t, err)

	return body.String()
}

func TestNilMetrics(t *testing.T) {
	var m *Metrics

	// Test that nil metrics don't panic
	t.Run("NilMetricsOperations", func(t *testing.T) {
		assert.NotPanics(t, func() {
			m.RecordConnection("test")
			m.RecordConnectionClosed()
			m.RecordCommand("test", true)
			m.RecordCommandDuration("test", time.Second)
			m.RecordBackendError()
			m.RecordCommandError("test", "error")
			_ = m.Close()
		})
	})
}
