package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
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
	if got := metrics.exportStatuses; len(got) != 2 || got[0] != "retry" || got[1] != "ok" {
		t.Fatalf("export statuses = %v, want [retry ok]", got)
	}
	if len(metrics.dropReasons) != 0 {
		t.Fatalf("drop reasons = %v, want none", metrics.dropReasons)
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
	if got := metrics.exportStatuses; len(got) != 1 || got[0] != "permanent_error" {
		t.Fatalf("export statuses = %v, want [permanent_error]", got)
	}
	if got := metrics.dropReasons; len(got) != 1 || got[0] != "permanent_error" {
		t.Fatalf("drop reasons = %v, want [permanent_error]", got)
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
	exportStatuses []string
	dropReasons    []string
	queueDepth     int
	queueCapacity  int
}

func (m *recordingMetrics) RecordOTelExport(status string, _ time.Duration, _ int) {
	m.exportStatuses = append(m.exportStatuses, status)
}

func (m *recordingMetrics) RecordOTelDrop(reason string, _ int) {
	m.dropReasons = append(m.dropReasons, reason)
}

func (m *recordingMetrics) SetOTelQueueDepth(depth int) {
	m.queueDepth = depth
}

func (m *recordingMetrics) SetOTelQueueCapacity(capacity int) {
	m.queueCapacity = capacity
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
