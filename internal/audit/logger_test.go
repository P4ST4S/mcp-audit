package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeStore is an in-memory Store used to capture appended entries.
type fakeStore struct {
	entries  []Entry
	appendOK bool
	failWith error
}

func newFakeStore() *fakeStore { return &fakeStore{appendOK: true} }

func (s *fakeStore) Append(entry Entry) error {
	if !s.appendOK {
		return s.failWith
	}
	s.entries = append(s.entries, entry)
	return nil
}
func (s *fakeStore) Query(QueryFilter) ([]Entry, error) { return s.entries, nil }
func (s *fakeStore) Stats() (Stats, error)              { return Stats{}, nil }
func (s *fakeStore) Close() error                       { return nil }

// fakeRedactor replaces any non-empty payload with `[REDACTED]`. Used to verify
// the Logger calls Redact on each redactable field.
type fakeRedactor struct {
	calls []string
}

func (r *fakeRedactor) Redact(raw json.RawMessage) json.RawMessage {
	r.calls = append(r.calls, string(raw))
	if len(raw) == 0 {
		return raw
	}
	return json.RawMessage(`"[REDACTED]"`)
}

type fakeMetrics struct {
	recorded []Entry
}

func (m *fakeMetrics) RecordAuditEntry(e Entry) { m.recorded = append(m.recorded, e) }

type fakeExporter struct {
	exported []Entry
	failWith error
}

func (e *fakeExporter) ExportAuditEntry(entry Entry) error {
	e.exported = append(e.exported, entry)
	return e.failWith
}

func TestLoggerRecordAssignsIDWhenMissing(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store})

	if err := logger.Record(Entry{Method: "ping"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(store.entries) != 1 {
		t.Fatalf("expected 1 stored entry, got %d", len(store.entries))
	}
	if store.entries[0].ID == "" {
		t.Fatal("expected an auto-generated ID")
	}
}

func TestLoggerRecordPreservesExistingID(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store})

	if err := logger.Record(Entry{ID: "explicit-id", Method: "ping"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if store.entries[0].ID != "explicit-id" {
		t.Fatalf("expected ID 'explicit-id', got %q", store.entries[0].ID)
	}
}

func TestLoggerRecordAssignsTimestampWhenZero(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store})

	before := time.Now().UTC()
	if err := logger.Record(Entry{Method: "ping"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	after := time.Now().UTC()

	got := store.entries[0].Timestamp
	if got.Before(before) || got.After(after) {
		t.Fatalf("timestamp %v not in [%v, %v]", got, before, after)
	}
	if got.Location() != time.UTC {
		t.Fatalf("expected UTC location, got %v", got.Location())
	}
}

func TestLoggerRecordPreservesExistingTimestamp(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store})

	fixed := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	if err := logger.Record(Entry{Method: "ping", Timestamp: fixed}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if !store.entries[0].Timestamp.Equal(fixed) {
		t.Fatalf("expected timestamp %v, got %v", fixed, store.entries[0].Timestamp)
	}
}

func TestLoggerRecordAppliesDefaultsFromConfig(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{
		Store:     store,
		Transport: "http",
		ClientID:  "default-client",
		ServerID:  "default-server",
	})

	if err := logger.Record(Entry{Method: "ping"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	got := store.entries[0]
	if got.Transport != "http" {
		t.Fatalf("expected default transport http, got %q", got.Transport)
	}
	if got.ClientID != "default-client" {
		t.Fatalf("expected default client id, got %q", got.ClientID)
	}
	if got.ServerID != "default-server" {
		t.Fatalf("expected default server id, got %q", got.ServerID)
	}
}

func TestLoggerRecordPreservesExplicitFields(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{
		Store:     store,
		Transport: "http",
		ClientID:  "default-client",
		ServerID:  "default-server",
	})

	entry := Entry{
		Method:    "ping",
		Transport: "stdio",
		ClientID:  "explicit-client",
		ServerID:  "explicit-server",
	}
	if err := logger.Record(entry); err != nil {
		t.Fatalf("record: %v", err)
	}
	got := store.entries[0]
	if got.Transport != "stdio" {
		t.Fatalf("explicit transport overridden by default: %q", got.Transport)
	}
	if got.ClientID != "explicit-client" {
		t.Fatalf("explicit client_id overridden: %q", got.ClientID)
	}
	if got.ServerID != "explicit-server" {
		t.Fatalf("explicit server_id overridden: %q", got.ServerID)
	}
}

func TestLoggerRecordAppliesRedactionToParamsResultAndErrorData(t *testing.T) {
	store := newFakeStore()
	redactor := &fakeRedactor{}
	logger := NewLogger(LoggerConfig{Store: store, Redactor: redactor})

	entry := Entry{
		Method: "tools/call",
		Params: json.RawMessage(`{"token":"abc"}`),
		Result: json.RawMessage(`{"secret":"xyz"}`),
		Error: &RPCError{
			Code:    -1,
			Message: "boom",
			Data:    json.RawMessage(`{"password":"123"}`),
		},
	}
	if err := logger.Record(entry); err != nil {
		t.Fatalf("record: %v", err)
	}

	if len(redactor.calls) != 3 {
		t.Fatalf("expected Redact called 3 times, got %d", len(redactor.calls))
	}
	stored := store.entries[0]
	if string(stored.Params) != `"[REDACTED]"` {
		t.Fatalf("params not redacted: %s", string(stored.Params))
	}
	if string(stored.Result) != `"[REDACTED]"` {
		t.Fatalf("result not redacted: %s", string(stored.Result))
	}
	if string(stored.Error.Data) != `"[REDACTED]"` {
		t.Fatalf("error data not redacted: %s", string(stored.Error.Data))
	}
}

func TestLoggerRecordSkipsRedactionWhenNoRedactor(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store})

	params := json.RawMessage(`{"token":"abc"}`)
	if err := logger.Record(Entry{Method: "tools/call", Params: params}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if string(store.entries[0].Params) != string(params) {
		t.Fatal("params should be untouched without a redactor")
	}
}

func TestLoggerRecordAppliesSignatureWhenSignerEnabled(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store, Signer: NewSigner("hunter2")})

	if err := logger.Record(Entry{Method: "ping"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if store.entries[0].Signature == "" {
		t.Fatal("expected entry to be signed")
	}
}

func TestLoggerRecordSkipsSignatureWhenSecretEmpty(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store, Signer: NewSigner("")})

	if err := logger.Record(Entry{Method: "ping"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if store.entries[0].Signature != "" {
		t.Fatalf("expected empty signature when secret is empty, got %q", store.entries[0].Signature)
	}
}

func TestLoggerRecordSignsAfterRedaction(t *testing.T) {
	// Signature must reflect the redacted Params (not the raw ones), so we sign
	// after the redactor runs. Verify by signing the same redacted entry
	// manually and comparing.
	store := newFakeStore()
	redactor := &fakeRedactor{}
	signer := NewSigner("hunter2")
	logger := NewLogger(LoggerConfig{Store: store, Redactor: redactor, Signer: signer})

	entry := Entry{
		ID:        "fixed-id",
		Timestamp: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		Method:    "tools/call",
		ToolName:  "read_file",
		Params:    json.RawMessage(`{"token":"raw"}`),
	}
	if err := logger.Record(entry); err != nil {
		t.Fatalf("record: %v", err)
	}

	stored := store.entries[0]
	expected := signer.Sign(Entry{
		ID:        "fixed-id",
		Timestamp: entry.Timestamp,
		Method:    "tools/call",
		ToolName:  "read_file",
		Params:    json.RawMessage(`"[REDACTED]"`),
	})
	if stored.Signature != expected {
		t.Fatalf("signature does not match redacted entry signature\nstored:   %s\nexpected: %s", stored.Signature, expected)
	}
}

func TestLoggerRecordWrapsStoreAppendError(t *testing.T) {
	store := newFakeStore()
	store.appendOK = false
	store.failWith = errors.New("disk full")
	logger := NewLogger(LoggerConfig{Store: store})

	err := logger.Record(Entry{Method: "ping"})
	if err == nil {
		t.Fatal("expected error when store.Append fails")
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("error should wrap the underlying error, got %v", err)
	}
	if !strings.Contains(err.Error(), "audit: logger: append") {
		t.Fatalf("error should include context prefix, got %v", err)
	}
}

func TestLoggerRecordCallsMetricsWhenSet(t *testing.T) {
	store := newFakeStore()
	metrics := &fakeMetrics{}
	logger := NewLogger(LoggerConfig{Store: store, Metrics: metrics})

	if err := logger.Record(Entry{Method: "ping"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(metrics.recorded) != 1 {
		t.Fatalf("expected metrics recorded once, got %d", len(metrics.recorded))
	}
}

func TestLoggerRecordCallsTraceExporterWhenSet(t *testing.T) {
	store := newFakeStore()
	exporter := &fakeExporter{}
	logger := NewLogger(LoggerConfig{Store: store, Trace: exporter})

	if err := logger.Record(Entry{Method: "tools/call"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(exporter.exported) != 1 {
		t.Fatalf("expected exporter called once, got %d", len(exporter.exported))
	}
}

func TestLoggerRecordIgnoresTraceExporterError(t *testing.T) {
	// Exporter failure must be logged but never propagated, otherwise an OTel
	// outage would surface as a proxy error to the user.
	store := newFakeStore()
	exporter := &fakeExporter{failWith: errors.New("collector unreachable")}
	logger := NewLogger(LoggerConfig{Store: store, Trace: exporter})

	if err := logger.Record(Entry{Method: "tools/call"}); err != nil {
		t.Fatalf("exporter errors should not propagate, got %v", err)
	}
	if len(store.entries) != 1 {
		t.Fatal("entry should still be stored even if exporter fails")
	}
}

func TestLoggerStoreReturnsConfiguredStore(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store})
	if logger.Store() != store {
		t.Fatal("Store() should return the configured store")
	}
}

func TestNewLoggerNilLogFallsBackToDefault(t *testing.T) {
	// Should not panic when Log is nil; verified by recording an entry that
	// triggers the internal slog.Debug call.
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store})
	if err := logger.Record(Entry{Method: "ping"}); err != nil {
		t.Fatalf("record: %v", err)
	}
}
