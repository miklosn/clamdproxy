// Package main implements metrics collection for clamdproxy using OpenTelemetry
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Metrics holds all the metrics instruments used by the proxy
type Metrics struct {
	ConnectionsTotal  metric.Int64Counter
	CommandsTotal     metric.Int64Counter
	CommandDuration   metric.Float64Histogram
	ActiveConnections metric.Int64UpDownCounter
	BackendErrors     metric.Int64Counter
	CommandErrors     metric.Int64Counter
	FilesScanned      metric.Int64Counter
	FilesSizeBytes    metric.Int64Counter
	FilesWithVirus    metric.Int64Counter
	metricServer      *http.Server
}

// Global metrics instance
var proxyMetrics *Metrics

// InitMetrics initializes the OpenTelemetry metrics system and creates all metric instruments
func InitMetrics(metricsAddr string) (*Metrics, error) {
	// Create a new Prometheus exporter
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}

	// Create a new MeterProvider with the Prometheus exporter
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
	)

	// Set the global MeterProvider
	otel.SetMeterProvider(provider)

	// Create a meter for our application
	meter := provider.Meter("clamdproxy")

	// Create metrics
	m := &Metrics{}

	// Initialize counters
	m.ConnectionsTotal, err = meter.Int64Counter(
		"clamdproxy_connections_total",
		metric.WithDescription("Total number of client connections"),
		metric.WithUnit("{connections}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create connections counter: %w", err)
	}

	m.CommandsTotal, err = meter.Int64Counter(
		"clamdproxy_commands_total",
		metric.WithDescription("Total number of commands processed"),
		metric.WithUnit("{commands}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create commands counter: %w", err)
	}

	m.CommandDuration, err = meter.Float64Histogram(
		"clamdproxy_command_duration_seconds",
		metric.WithDescription("Duration of command processing in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create command duration histogram: %w", err)
	}

	m.ActiveConnections, err = meter.Int64UpDownCounter(
		"clamdproxy_active_connections",
		metric.WithDescription("Current number of active connections"),
		metric.WithUnit("{connections}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create active connections counter: %w", err)
	}

	m.BackendErrors, err = meter.Int64Counter(
		"clamdproxy_backend_errors_total",
		metric.WithDescription("Total number of backend connection errors"),
		metric.WithUnit("{errors}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend errors counter: %w", err)
	}

	m.CommandErrors, err = meter.Int64Counter(
		"clamdproxy_command_errors_total",
		metric.WithDescription("Total number of command processing errors"),
		metric.WithUnit("{errors}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create command errors counter: %w", err)
	}

	// Initialize file scanning metrics
	m.FilesScanned, err = meter.Int64Counter(
		"clamdproxy_files_scanned_total",
		metric.WithDescription("Total number of files scanned"),
		metric.WithUnit("{files}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create files scanned counter: %w", err)
	}

	m.FilesSizeBytes, err = meter.Int64Counter(
		"clamdproxy_files_size_bytes_total",
		metric.WithDescription("Total size of files scanned in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create file size counter: %w", err)
	}

	m.FilesWithVirus, err = meter.Int64Counter(
		"clamdproxy_files_with_virus_total",
		metric.WithDescription("Total number of files with viruses detected"),
		metric.WithUnit("{files}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create files with virus counter: %w", err)
	}

	// Start metrics HTTP server if address is provided
	if metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		m.metricServer = &http.Server{
			Addr:    metricsAddr,
			Handler: mux,
		}

		go func() {
			logger.Info("Starting metrics server", "addr", metricsAddr)
			if err := m.metricServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("Metrics server failed", "error", err)
			}
		}()
	}

	proxyMetrics = m
	return m, nil
}

// RecordConnection records a new client connection
func (m *Metrics) RecordConnection(clientAddr string) {
	if m == nil {
		return
	}
	m.ConnectionsTotal.Add(context.Background(), 1)
	m.ActiveConnections.Add(context.Background(), 1)
}

// RecordConnectionClosed records a closed client connection
func (m *Metrics) RecordConnectionClosed() {
	if m == nil {
		return
	}
	m.ActiveConnections.Add(context.Background(), -1)
}

// RecordCommand records a command being processed
func (m *Metrics) RecordCommand(cmd string, allowed bool) {
	if m == nil {
		return
	}
	m.CommandsTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("command", cmd),
		attribute.Bool("allowed", allowed),
	))
}

// RecordCommandDuration records the duration of a command
func (m *Metrics) RecordCommandDuration(cmd string, duration time.Duration) {
	if m == nil {
		return
	}
	m.CommandDuration.Record(context.Background(), duration.Seconds(), metric.WithAttributes(
		attribute.String("command", cmd),
	))
}

// RecordBackendError records a backend connection error
func (m *Metrics) RecordBackendError() {
	if m == nil {
		return
	}
	m.BackendErrors.Add(context.Background(), 1)
}

// RecordCommandError records a command processing error
func (m *Metrics) RecordCommandError(cmd string, errMsg string) {
	if m == nil {
		return
	}
	m.CommandErrors.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("command", cmd),
		attribute.String("error", errMsg),
	))
}

// RecordFileScan records metrics for a scanned file
func (m *Metrics) RecordFileScan(filename string, sizeBytes int64, virusFound bool, virusName string) {
	if m == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.Bool("virus_detected", virusFound),
	}

	m.FilesScanned.Add(context.Background(), 1, metric.WithAttributes(attrs...))
	m.FilesSizeBytes.Add(context.Background(), sizeBytes, metric.WithAttributes(attrs...))

	if virusFound {
		m.FilesWithVirus.Add(context.Background(), 1, metric.WithAttributes(attrs...))

		// Log the detailed information instead of adding it as a label
		logger.Info("Virus detected",
			"filename", filename,
			"virus_name", virusName,
			"size_bytes", sizeBytes)
	}
}

// Close shuts down the metrics server if it's running
func (m *Metrics) Close() error {
	if m == nil || m.metricServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return m.metricServer.Shutdown(ctx)
}
