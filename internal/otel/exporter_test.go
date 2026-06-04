package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

func TestSpanFromEntryUsesMCPSemanticConventions(t *testing.T) {
	exporter, err := NewExporter(Config{
		Endpoint:        "http://localhost:4318",
		ServiceName:     "mcp-audit-test",
		Storage:         "jsonl",
		Upstream:        "http://localhost:8080",
		FlushIntervalMS: 10000,
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	defer exporter.Close(context.Background())

	entry := audit.Entry{
		ID:         "01HY8G6Y8S6W9K6ZD7VJ4Q8X4R",
		Timestamp:  time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		Direction:  audit.DirectionServerToClient,
		Transport:  "http",
		Method:     "tools/call",
		RequestID:  "42",
		ToolName:   "read_file",
		Result:     json.RawMessage(`{"isError":true}`),
		DurationMs: 25,
		ClientID:   "claude-desktop",
		ServerID:   "filesystem",
		Signature:  "abc123",
	}
	span, err := exporter.spanFromEntry(entry)
	if err != nil {
		t.Fatalf("span from entry: %v", err)
	}

	if span.Name != "tools/call read_file" {
		t.Fatalf("span name = %q", span.Name)
	}
	if len(span.TraceID) != 32 {
		t.Fatalf("trace id length = %d, want 32", len(span.TraceID))
	}
	if len(span.SpanID) != 16 {
		t.Fatalf("span id length = %d, want 16", len(span.SpanID))
	}
	if span.Status.Code != statusCodeError {
		t.Fatalf("status code = %d, want error", span.Status.Code)
	}
	attrs := attrMap(span.Attributes)
	assertStringAttr(t, attrs, attrMCPMethodName, "tools/call")
	assertStringAttr(t, attrs, attrJSONRPCRequestID, "42")
	assertStringAttr(t, attrs, attrGenAIOperationName, "execute_tool")
	assertStringAttr(t, attrs, attrGenAIToolName, "read_file")
	assertStringAttr(t, attrs, attrNetworkTransport, "tcp")
	assertStringAttr(t, attrs, attrNetworkProtocolName, "http")
	assertStringAttr(t, attrs, attrErrorType, "tool_error")
	assertStringAttr(t, attrs, attrMCPAuditEntryID, entry.ID)
	assertStringAttr(t, attrs, attrMCPAuditDirection, "server_to_client")
	assertBoolAttr(t, attrs, attrMCPAuditSignaturePresent, true)
	assertStringAttr(t, attrs, attrMCPAuditStorage, "jsonl")
	assertStringAttr(t, attrs, attrServerAddress, "localhost")
	assertIntAttr(t, attrs, attrServerPort, "8080")
}

func TestExporterPostsOTLPHTTPJSON(t *testing.T) {
	requests := make(chan tracesPayload, 1)
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/traces" {
			t.Fatalf("path = %q, want /v1/traces", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content-type = %q", got)
		}
		var payload tracesPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		requests <- payload
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     make(http.Header),
		}, nil
	})

	exporter, err := NewExporter(Config{
		Endpoint:        "http://collector.local",
		ServiceName:     "mcp-audit-test",
		QueueSize:       2,
		BatchSize:       1,
		FlushIntervalMS: 10000,
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	exporter.client.Transport = transport
	if err := exporter.ExportAuditEntry(audit.Entry{
		ID:        "01HY8G6Y8S6W9K6ZD7VJ4Q8X4R",
		Timestamp: time.Now().UTC(),
		Transport: "stdio",
		Method:    "tools/call",
		ToolName:  "read_file",
	}); err != nil {
		t.Fatalf("export audit entry: %v", err)
	}

	select {
	case payload := <-requests:
		spans := payload.ResourceSpans[0].ScopeSpans[0].Spans
		if len(spans) != 1 {
			t.Fatalf("spans = %d, want 1", len(spans))
		}
		assertStringAttr(t, attrMap(spans[0].Attributes), attrNetworkTransport, "pipe")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for otlp export")
	}

	if err := exporter.Close(context.Background()); err != nil {
		t.Fatalf("close exporter: %v", err)
	}
}

func TestNewExporterAppliesDefaultsAndNormalization(t *testing.T) {
	exporter, err := NewExporter(Config{
		Endpoint:        "http://collector.local/custom",
		ServiceName:     "",
		QueueSize:       -1,
		BatchSize:       -1,
		FlushIntervalMS: -1,
		TimeoutMS:       -1,
		MaxRetries:      -1,
		RetryInitialMS:  -1,
		RetryMaxMS:      1,
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	defer exporter.Close(context.Background())

	if exporter.config.ServiceName != defaultServiceName {
		t.Fatalf("service name = %q, want %q", exporter.config.ServiceName, defaultServiceName)
	}
	if cap(exporter.entries) != defaultQueueSize {
		t.Fatalf("queue capacity = %d, want %d", cap(exporter.entries), defaultQueueSize)
	}
	if exporter.config.BatchSize != defaultBatchSize {
		t.Fatalf("batch size = %d, want %d", exporter.config.BatchSize, defaultBatchSize)
	}
	if exporter.config.FlushIntervalMS != defaultFlushIntervalMS {
		t.Fatalf("flush interval = %d, want %d", exporter.config.FlushIntervalMS, defaultFlushIntervalMS)
	}
	if exporter.config.TimeoutMS != defaultTimeoutMS {
		t.Fatalf("timeout = %d, want %d", exporter.config.TimeoutMS, defaultTimeoutMS)
	}
	if exporter.config.MaxRetries != 0 {
		t.Fatalf("max retries = %d, want 0", exporter.config.MaxRetries)
	}
	if exporter.config.RetryInitialMS != defaultRetryInitialMS {
		t.Fatalf("retry initial = %d, want %d", exporter.config.RetryInitialMS, defaultRetryInitialMS)
	}
	if exporter.config.RetryMaxMS != defaultRetryInitialMS {
		t.Fatalf("retry max = %d, want %d", exporter.config.RetryMaxMS, defaultRetryInitialMS)
	}
	if exporter.endpoint != "http://collector.local/custom/v1/traces" {
		t.Fatalf("endpoint = %q", exporter.endpoint)
	}
}

func TestNewExporterRejectsInvalidEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
	}{
		{name: "parse error", endpoint: "http://%zz"},
		{name: "missing scheme", endpoint: "collector.local:4318"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewExporter(Config{
				Endpoint:        tc.endpoint,
				ServiceName:     "mcp-audit-test",
				QueueSize:       1,
				BatchSize:       1,
				FlushIntervalMS: 10000,
			})
			if err == nil {
				t.Fatal("expected endpoint error")
			}
		})
	}
}

func TestExportAuditEntryEdgeCases(t *testing.T) {
	var nilExporter *Exporter
	if err := nilExporter.ExportAuditEntry(audit.Entry{Method: "tools/call"}); err != nil {
		t.Fatalf("nil exporter error = %v, want nil", err)
	}

	metrics := &recordingMetrics{}
	exporter := &Exporter{
		entries: make(chan audit.Entry, 1),
		metrics: metrics,
	}
	if err := exporter.ExportAuditEntry(audit.Entry{Method: "ping"}); err != nil {
		t.Fatalf("non tools/call export error = %v", err)
	}
	if len(exporter.entries) != 0 {
		t.Fatalf("non tools/call queued entries = %d, want 0", len(exporter.entries))
	}
	if err := exporter.ExportAuditEntry(audit.Entry{Method: "tools/call"}); err != nil {
		t.Fatalf("first export error = %v", err)
	}
	if got := metrics.queueDepthValue(); got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
	if err := exporter.ExportAuditEntry(audit.Entry{Method: "tools/call"}); err == nil {
		t.Fatal("expected queue full error")
	}
	if got := metrics.dropReasonsSnapshot(); len(got) != 1 || got[0] != "queue_full" {
		t.Fatalf("drop reasons = %v, want [queue_full]", got)
	}

	closedExporter := &Exporter{entries: make(chan audit.Entry, 1)}
	closedExporter.closed.Store(true)
	if err := closedExporter.ExportAuditEntry(audit.Entry{Method: "tools/call"}); err == nil {
		t.Fatal("expected closed exporter error")
	}
}

func TestExporterAddsConfiguredHeaders(t *testing.T) {
	called := false
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization header = %q", got)
		}
		if got := r.Header.Get("X-Api-Key"); got != "test-key" {
			t.Fatalf("x-api-key header = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "mcp-audit-otlp/1" {
			t.Fatalf("user-agent = %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     make(http.Header),
		}, nil
	})

	exporter, err := NewExporter(Config{
		Endpoint:        "http://collector.local",
		ServiceName:     "mcp-audit-test",
		QueueSize:       1,
		BatchSize:       1,
		FlushIntervalMS: 10000,
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
			"X-Api-Key":     "test-key",
		},
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	defer exporter.Close(context.Background())
	exporter.client.Transport = transport

	exporter.exportPayload([]byte(`{"resourceSpans":[]}`), 1)
	if !called {
		t.Fatal("transport was not called")
	}
}

func TestExporterRetriesRetryableOTLPFailures(t *testing.T) {
	attempts := 0
	metrics := &recordingMetrics{}
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(bytes.NewReader([]byte("collector unavailable"))),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     make(http.Header),
		}, nil
	})

	exporter, err := NewExporter(Config{
		Endpoint:        "http://collector.local",
		ServiceName:     "mcp-audit-test",
		QueueSize:       1,
		BatchSize:       1,
		FlushIntervalMS: 10000,
		MaxRetries:      1,
		RetryInitialMS:  1,
		RetryMaxMS:      1,
		Metrics:         metrics,
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	defer exporter.Close(context.Background())
	exporter.client.Transport = transport

	exporter.exportPayload([]byte(`{"resourceSpans":[]}`), 2)
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if got := metrics.exportStatusesSnapshot(); len(got) != 2 || got[0] != "retry" || got[1] != "ok" {
		t.Fatalf("export statuses = %v, want [retry ok]", got)
	}
	if got := metrics.dropReasonsSnapshot(); len(got) != 0 {
		t.Fatalf("drop reasons = %v, want none", got)
	}
}

func TestExporterDoesNotRetryPermanentOTLPFailures(t *testing.T) {
	attempts := 0
	metrics := &recordingMetrics{}
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(bytes.NewReader([]byte("invalid payload"))),
			Header:     make(http.Header),
		}, nil
	})

	exporter, err := NewExporter(Config{
		Endpoint:        "http://collector.local",
		ServiceName:     "mcp-audit-test",
		QueueSize:       1,
		BatchSize:       1,
		FlushIntervalMS: 10000,
		MaxRetries:      3,
		RetryInitialMS:  1,
		RetryMaxMS:      1,
		Metrics:         metrics,
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	defer exporter.Close(context.Background())
	exporter.client.Transport = transport

	exporter.exportPayload([]byte(`{"resourceSpans":[]}`), 2)
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if got := metrics.exportStatusesSnapshot(); len(got) != 1 || got[0] != "permanent_error" {
		t.Fatalf("export statuses = %v, want [permanent_error]", got)
	}
	if got := metrics.dropReasonsSnapshot(); len(got) != 1 || got[0] != "permanent_error" {
		t.Fatalf("drop reasons = %v, want [permanent_error]", got)
	}
}

func TestExporterRecordsDropAfterRetryExhaustion(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "collector unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	metrics := &recordingMetrics{}
	exporter, err := NewExporter(Config{
		Endpoint:        ts.URL,
		ServiceName:     "mcp-audit-test",
		QueueSize:       1,
		BatchSize:       1,
		FlushIntervalMS: 10000,
		MaxRetries:      2,
		RetryInitialMS:  1,
		RetryMaxMS:      1,
		Metrics:         metrics,
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	defer exporter.Close(context.Background())

	exporter.exportPayload([]byte(`{"resourceSpans":[]}`), 3)

	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
	wantStatuses := []string{"retry", "retry", "error"}
	if got := metrics.exportStatusesSnapshot(); !slices.Equal(got, wantStatuses) {
		t.Fatalf("export statuses = %v, want %v", got, wantStatuses)
	}
	if got := metrics.dropReasonsSnapshot(); len(got) != 1 || got[0] != "error" {
		t.Fatalf("drop reasons = %v, want [error]", got)
	}
}

func TestExporterParsesRetryAfterHeader(t *testing.T) {
	future := time.Now().UTC().Add(2 * time.Second).Format(http.TimeFormat)
	cases := []struct {
		name       string
		header     string
		wantExact  time.Duration
		wantFuture bool
	}{
		{name: "seconds", header: "1", wantExact: time.Second},
		{name: "future http date", header: future, wantFuture: true},
		{name: "past http date", header: time.Now().UTC().Add(-time.Second).Format(http.TimeFormat), wantExact: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", tc.header)
				http.Error(w, "retry later", http.StatusServiceUnavailable)
			}))
			defer ts.Close()

			exporter, err := NewExporter(Config{
				Endpoint:        ts.URL,
				ServiceName:     "mcp-audit-test",
				QueueSize:       1,
				BatchSize:       1,
				FlushIntervalMS: 10000,
			})
			if err != nil {
				t.Fatalf("new exporter: %v", err)
			}
			defer exporter.Close(context.Background())

			status, retryAfter, _, err := exporter.postPayload([]byte(`{"resourceSpans":[]}`))
			if err != nil {
				t.Fatalf("post payload: %v", err)
			}
			if status != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", status, http.StatusServiceUnavailable)
			}
			if tc.wantFuture {
				if retryAfter <= 0 || retryAfter > 2*time.Second {
					t.Fatalf("retryAfter = %s, want positive duration up to 2s", retryAfter)
				}
				return
			}
			if retryAfter != tc.wantExact {
				t.Fatalf("retryAfter = %s, want %s", retryAfter, tc.wantExact)
			}
		})
	}
}

func TestExporterClassifiesPermanentAndRetryableStatuses(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		wantAttempts int32
		wantStatuses []string
		wantDrops    []string
	}{
		{name: "bad request", status: http.StatusBadRequest, wantAttempts: 1, wantStatuses: []string{"permanent_error"}, wantDrops: []string{"permanent_error"}},
		{name: "not found", status: http.StatusNotFound, wantAttempts: 1, wantStatuses: []string{"permanent_error"}, wantDrops: []string{"permanent_error"}},
		{name: "not implemented", status: http.StatusNotImplemented, wantAttempts: 1, wantStatuses: []string{"permanent_error"}, wantDrops: []string{"permanent_error"}},
		{name: "request timeout", status: http.StatusRequestTimeout, wantAttempts: 2, wantStatuses: []string{"retry", "error"}, wantDrops: []string{"error"}},
		{name: "too many requests", status: http.StatusTooManyRequests, wantAttempts: 2, wantStatuses: []string{"retry", "error"}, wantDrops: []string{"error"}},
		{name: "internal server error", status: http.StatusInternalServerError, wantAttempts: 2, wantStatuses: []string{"retry", "error"}, wantDrops: []string{"error"}},
		{name: "bad gateway", status: http.StatusBadGateway, wantAttempts: 2, wantStatuses: []string{"retry", "error"}, wantDrops: []string{"error"}},
		{name: "service unavailable", status: http.StatusServiceUnavailable, wantAttempts: 2, wantStatuses: []string{"retry", "error"}, wantDrops: []string{"error"}},
		{name: "gateway timeout", status: http.StatusGatewayTimeout, wantAttempts: 2, wantStatuses: []string{"retry", "error"}, wantDrops: []string{"error"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				http.Error(w, http.StatusText(tc.status), tc.status)
			}))
			defer ts.Close()

			metrics := &recordingMetrics{}
			exporter, err := NewExporter(Config{
				Endpoint:        ts.URL,
				ServiceName:     "mcp-audit-test",
				QueueSize:       1,
				BatchSize:       1,
				FlushIntervalMS: 10000,
				MaxRetries:      1,
				RetryInitialMS:  1,
				RetryMaxMS:      1,
				Metrics:         metrics,
			})
			if err != nil {
				t.Fatalf("new exporter: %v", err)
			}
			defer exporter.Close(context.Background())

			exporter.exportPayload([]byte(`{"resourceSpans":[]}`), 1)

			if got := attempts.Load(); got != tc.wantAttempts {
				t.Fatalf("attempts = %d, want %d", got, tc.wantAttempts)
			}
			if got := metrics.exportStatusesSnapshot(); !slices.Equal(got, tc.wantStatuses) {
				t.Fatalf("export statuses = %v, want %v", got, tc.wantStatuses)
			}
			if got := metrics.dropReasonsSnapshot(); !slices.Equal(got, tc.wantDrops) {
				t.Fatalf("drop reasons = %v, want %v", got, tc.wantDrops)
			}
		})
	}
}

func TestExporterAppliesConfiguredHeadersOnRetries(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("attempt %d authorization header = %q", attempt, got)
		}
		if got := r.Header.Get("X-Api-Key"); got != "test-key" {
			t.Fatalf("attempt %d x-api-key header = %q", attempt, got)
		}
		if attempt == 1 {
			http.Error(w, "collector unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	exporter, err := NewExporter(Config{
		Endpoint:        ts.URL,
		ServiceName:     "mcp-audit-test",
		QueueSize:       1,
		BatchSize:       1,
		FlushIntervalMS: 10000,
		MaxRetries:      1,
		RetryInitialMS:  1,
		RetryMaxMS:      1,
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
			"X-Api-Key":     "test-key",
		},
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	defer exporter.Close(context.Background())

	exporter.exportPayload([]byte(`{"resourceSpans":[]}`), 1)

	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestExporterCloseContextCanInterruptWaitDuringRetrySleep(t *testing.T) {
	requestSeen := make(chan struct{})
	var seen atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen.CompareAndSwap(false, true) {
			close(requestSeen)
		}
		w.Header().Set("Retry-After", "1")
		http.Error(w, "collector unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	exporter, err := NewExporter(Config{
		Endpoint:        ts.URL,
		ServiceName:     "mcp-audit-test",
		QueueSize:       1,
		BatchSize:       1,
		FlushIntervalMS: 10000,
		MaxRetries:      1,
		Metrics:         &recordingMetrics{},
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}

	if err := exporter.ExportAuditEntry(audit.Entry{Method: "tools/call"}); err != nil {
		t.Fatalf("export audit entry: %v", err)
	}
	select {
	case <-requestSeen:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first export attempt")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err = exporter.Close(ctx)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("close during retry sleep error = %v, want context deadline exceeded", err)
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cleanupCancel()
	if err := exporter.Close(cleanupCtx); err != nil {
		t.Fatalf("cleanup close: %v", err)
	}
}

func TestExporterRejectsInvalidTLSCAFilePEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(path, []byte("not a pem certificate"), 0o600); err != nil {
		t.Fatalf("write invalid ca: %v", err)
	}

	_, err := NewExporter(Config{
		Endpoint:        "https://collector.local",
		ServiceName:     "mcp-audit-test",
		QueueSize:       1,
		BatchSize:       1,
		FlushIntervalMS: 10000,
		TLSCAFile:       path,
	})
	if err == nil {
		t.Fatal("expected invalid TLS CA file error")
	}
	if !strings.Contains(err.Error(), "parse tls ca file") {
		t.Fatalf("error = %v, want parse tls ca file", err)
	}
}

func TestExporterRejectsInvalidTLSCAFile(t *testing.T) {
	_, err := NewExporter(Config{
		Endpoint:        "https://collector.local",
		ServiceName:     "mcp-audit-test",
		QueueSize:       1,
		BatchSize:       1,
		FlushIntervalMS: 10000,
		TLSCAFile:       t.TempDir() + "/missing-ca.pem",
	})
	if err == nil {
		t.Fatal("expected TLS CA file error")
	}
}

func TestSpanFromEntryUsesJSONRPCErrorTypes(t *testing.T) {
	exporter := &Exporter{}
	cases := []struct {
		name      string
		code      int
		wantError string
	}{
		{name: "rate limited", code: -32029, wantError: "rate_limited"},
		{name: "policy denied", code: -32030, wantError: "policy_denied"},
		{name: "generic jsonrpc", code: -32603, wantError: "jsonrpc_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			span, err := exporter.spanFromEntry(audit.Entry{
				ID:         "entry-" + tc.name,
				Timestamp:  time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
				Direction:  audit.DirectionClientToServer,
				Transport:  "stdio",
				Method:     "tools/call",
				DurationMs: -1,
				Error:      &audit.RPCError{Code: tc.code, Message: "failed"},
			})
			if err != nil {
				t.Fatalf("span from entry: %v", err)
			}
			if span.Status.Code != statusCodeError || span.Status.Message != "failed" {
				t.Fatalf("status = %+v, want error failed", span.Status)
			}
			if span.StartTimeUnixNano != span.EndTimeUnixNano {
				t.Fatalf("negative duration start = %s, end = %s, want equal", span.StartTimeUnixNano, span.EndTimeUnixNano)
			}
			assertStringAttr(t, attrMap(span.Attributes), attrErrorType, tc.wantError)
		})
	}
}

func TestTracesEndpointKeepsExistingPath(t *testing.T) {
	endpoint, err := tracesEndpoint("http://collector.local/v1/traces")
	if err != nil {
		t.Fatalf("traces endpoint with suffix: %v", err)
	}
	if endpoint != "http://collector.local/v1/traces" {
		t.Fatalf("endpoint with suffix = %q", endpoint)
	}
}

func TestTracesEndpointRejectsInvalidURL(t *testing.T) {
	if _, err := tracesEndpoint("http://%zz"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestUpstreamAddressParsesDefaultsAndExplicitPort(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		wantHost string
		wantPort int
	}{
		{name: "http default port", upstream: "http://127.0.0.1", wantHost: "127.0.0.1", wantPort: 80},
		{name: "https default port", upstream: "https://example.com", wantHost: "example.com", wantPort: 443},
		{name: "explicit port", upstream: "http://example.com:4318", wantHost: "example.com", wantPort: 4318},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := upstreamAddress(tc.upstream)
			if host != tc.wantHost || port != tc.wantPort {
				t.Fatalf("upstream address = %s:%d, want %s:%d", host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestUpstreamAddressRejectsInvalidURL(t *testing.T) {
	host, port := upstreamAddress("not a url")
	if host != "" || port != 0 {
		t.Fatalf("invalid upstream = %s:%d, want empty", host, port)
	}
}

func TestCopyHeadersIgnoresBlankKeys(t *testing.T) {
	headers := copyHeaders(map[string]string{"": "ignored", "Authorization": "Bearer token"})
	if len(headers) != 1 || headers["Authorization"] != "Bearer token" {
		t.Fatalf("headers = %v, want only Authorization", headers)
	}
}

func TestSpanNameWithoutToolUsesMethod(t *testing.T) {
	if got := spanName(audit.Entry{Method: "ping"}); got != "ping" {
		t.Fatalf("spanName without tool = %q, want ping", got)
	}
}

func TestNetworkTransportKeepsUnknownTransport(t *testing.T) {
	if got := networkTransport("unix"); got != "unix" {
		t.Fatalf("networkTransport = %q, want unix", got)
	}
}

func TestNormalizeDirectionDefaultsToUnknown(t *testing.T) {
	if got := normalizeDirection(""); got != "unknown" {
		t.Fatalf("normalizeDirection empty = %q, want unknown", got)
	}
}

func TestToolResultIsErrorIgnoresInvalidJSON(t *testing.T) {
	if toolResultIsError(json.RawMessage(`not-json`)) {
		t.Fatal("invalid tool result should not be an error")
	}
}

func TestAuditLoggerExportsSpanEndToEnd(t *testing.T) {
	requests := make(chan []byte, 1)
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		requests <- raw
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     make(http.Header),
		}, nil
	})

	exporter, err := NewExporter(Config{
		Endpoint:        "http://collector.local",
		ServiceName:     "mcp-audit-test",
		Storage:         "jsonl",
		QueueSize:       4,
		BatchSize:       1,
		FlushIntervalMS: 10000,
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	exporter.client.Transport = transport

	store := &memoryStore{}
	logger := audit.NewLogger(audit.LoggerConfig{
		Store:     store,
		Signer:    audit.NewSigner("test-secret"),
		Transport: "stdio",
		ClientID:  "claude-desktop",
		ServerID:  "filesystem",
		Trace:     exporter,
	})
	err = logger.Record(audit.Entry{
		Timestamp:  time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		Direction:  audit.DirectionClientToServer,
		Method:     "tools/call",
		RequestID:  "req-1",
		ToolName:   "read_file",
		Params:     json.RawMessage(`{"name":"read_file","arguments":{"path":"/tmp/secret.txt"}}`),
		DurationMs: 12,
	})
	if err != nil {
		t.Fatalf("record audit entry: %v", err)
	}

	select {
	case raw := <-requests:
		if bytes.Contains(raw, []byte("secret.txt")) {
			t.Fatalf("OTLP payload leaked params/result: %s", string(raw))
		}
		var payload tracesPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		span := payload.ResourceSpans[0].ScopeSpans[0].Spans[0]
		attrs := attrMap(span.Attributes)
		assertStringAttr(t, attrs, attrJSONRPCRequestID, "req-1")
		assertStringAttr(t, attrs, attrGenAIToolName, "read_file")
		assertStringAttr(t, attrs, attrMCPAuditEntryID, store.entries[0].ID)
		assertBoolAttr(t, attrs, attrMCPAuditSignaturePresent, true)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for otlp export")
	}

	if len(store.entries) != 1 {
		t.Fatalf("stored entries = %d, want 1", len(store.entries))
	}
	if store.entries[0].Signature == "" {
		t.Fatal("stored entry was not signed")
	}
	if err := exporter.Close(context.Background()); err != nil {
		t.Fatalf("close exporter: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type recordingMetrics struct {
	mu             sync.Mutex
	exportStatuses []string
	dropReasons    []string
	queueDepth     int
	queueCapacity  int
}

func (m *recordingMetrics) RecordOTelExport(status string, _ time.Duration, _ int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exportStatuses = append(m.exportStatuses, status)
}

func (m *recordingMetrics) RecordOTelDrop(reason string, _ int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropReasons = append(m.dropReasons, reason)
}

func (m *recordingMetrics) SetOTelQueueDepth(depth int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queueDepth = depth
}

func (m *recordingMetrics) SetOTelQueueCapacity(capacity int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queueCapacity = capacity
}

func (m *recordingMetrics) exportStatusesSnapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.exportStatuses)
}

func (m *recordingMetrics) dropReasonsSnapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.dropReasons)
}

func (m *recordingMetrics) queueDepthValue() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.queueDepth
}

func attrMap(attrs []keyValue) map[string]anyValue {
	out := make(map[string]anyValue, len(attrs))
	for _, attr := range attrs {
		out[attr.Key] = attr.Value
	}
	return out
}

func assertStringAttr(t *testing.T, attrs map[string]anyValue, key string, want string) {
	t.Helper()
	got, ok := attrs[key]
	if !ok {
		t.Fatalf("missing attribute %q", key)
	}
	if got.StringValue != want {
		t.Fatalf("%s = %q, want %q", key, got.StringValue, want)
	}
}

func assertIntAttr(t *testing.T, attrs map[string]anyValue, key string, want string) {
	t.Helper()
	got, ok := attrs[key]
	if !ok {
		t.Fatalf("missing attribute %q", key)
	}
	if got.IntValue != want {
		t.Fatalf("%s = %q, want %q", key, got.IntValue, want)
	}
}

func assertBoolAttr(t *testing.T, attrs map[string]anyValue, key string, want bool) {
	t.Helper()
	got, ok := attrs[key]
	if !ok {
		t.Fatalf("missing attribute %q", key)
	}
	if got.BoolValue == nil || *got.BoolValue != want {
		t.Fatalf("%s = %v, want %v", key, got.BoolValue, want)
	}
}

type memoryStore struct {
	entries []audit.Entry
}

func (s *memoryStore) Append(entry audit.Entry) error {
	s.entries = append(s.entries, entry)
	return nil
}

func (s *memoryStore) Query(audit.QueryFilter) ([]audit.Entry, error) {
	return append([]audit.Entry(nil), s.entries...), nil
}

func (s *memoryStore) Stats() (audit.Stats, error) {
	return audit.Stats{}, nil
}

func (s *memoryStore) Close() error {
	return nil
}
