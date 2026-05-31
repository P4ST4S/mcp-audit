package storage

import (
	"errors"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

// fakeStore is a minimal in-memory Store for instrumented tests.
type fakeStore struct {
	appendErr  error
	appendN    int
	batchErr   error
	batchN     int
	appendFunc func(entry audit.Entry) error
}

func (s *fakeStore) Append(entry audit.Entry) error {
	s.appendN++
	if s.appendFunc != nil {
		return s.appendFunc(entry)
	}
	return s.appendErr
}

func (s *fakeStore) AppendBatch(entries []audit.Entry) error {
	s.batchN++
	return s.batchErr
}

func (s *fakeStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	return []audit.Entry{{ID: "q1"}}, nil
}

func (s *fakeStore) Stats() (audit.Stats, error) {
	return audit.Stats{TotalToday: 42}, nil
}

func (s *fakeStore) Close() error { return nil }

// fakeStoreNoBatch is a Store that does NOT implement batchAppender.
type fakeStoreNoBatch struct {
	appendErr  error
	appendN    int
	appendFunc func(n int) error
}

func (s *fakeStoreNoBatch) Append(entry audit.Entry) error {
	s.appendN++
	if s.appendFunc != nil {
		return s.appendFunc(s.appendN)
	}
	return s.appendErr
}

func (s *fakeStoreNoBatch) Query(_ audit.QueryFilter) ([]audit.Entry, error) { return nil, nil }
func (s *fakeStoreNoBatch) Stats() (audit.Stats, error)                      { return audit.Stats{}, nil }
func (s *fakeStoreNoBatch) Close() error                                     { return nil }

// fakeMetrics records RecordStorageWrite calls.
type fakeMetrics struct {
	calls []storageWriteCall
}

type storageWriteCall struct {
	backend, mode, status string
	entries               int
}

func (m *fakeMetrics) RecordStorageWrite(backend, mode, status string, _ time.Duration, entries int) {
	m.calls = append(m.calls, storageWriteCall{backend, mode, status, entries})
}

func TestInstrumentedStoreAppendRecordsSuccessMetric(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	metrics := &fakeMetrics{}
	s := NewInstrumentedStore(store, metrics, "sqlite", "async")

	if err := s.Append(audit.Entry{ID: "e1"}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if len(metrics.calls) != 1 {
		t.Fatalf("expected 1 metric call, got %d", len(metrics.calls))
	}
	c := metrics.calls[0]
	if c.backend != "sqlite" || c.mode != "async" || c.status != "ok" || c.entries != 1 {
		t.Fatalf("unexpected metric call: %+v", c)
	}
}

func TestInstrumentedStoreAppendRecordsErrorMetric(t *testing.T) {
	t.Parallel()
	store := &fakeStore{appendErr: errors.New("disk full")}
	metrics := &fakeMetrics{}
	s := NewInstrumentedStore(store, metrics, "jsonl", "sync")

	_ = s.Append(audit.Entry{ID: "e1"})

	if len(metrics.calls) != 1 {
		t.Fatalf("expected 1 metric call, got %d", len(metrics.calls))
	}
	if metrics.calls[0].status != "error" {
		t.Fatalf("expected status=error, got %s", metrics.calls[0].status)
	}
}

func TestInstrumentedStoreAppendBatchUsesNativeBatchWhenAvailable(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	metrics := &fakeMetrics{}
	s := NewInstrumentedStore(store, metrics, "sqlite", "async")

	entries := []audit.Entry{{ID: "1"}, {ID: "2"}, {ID: "3"}}
	if err := s.AppendBatch(entries); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	if store.batchN != 1 {
		t.Fatalf("expected AppendBatch called once on inner store, got %d", store.batchN)
	}
	if store.appendN != 0 {
		t.Fatalf("expected Append not called on inner store, got %d", store.appendN)
	}
	if len(metrics.calls) != 1 || metrics.calls[0].entries != 3 {
		t.Fatalf("expected metric with entries=3, got %+v", metrics.calls)
	}
}

func TestInstrumentedStoreAppendBatchFallsBackToSingleAppend(t *testing.T) {
	t.Parallel()
	store := &fakeStoreNoBatch{}
	metrics := &fakeMetrics{}
	s := NewInstrumentedStore(store, metrics, "jsonl", "sync")

	entries := []audit.Entry{{ID: "1"}, {ID: "2"}, {ID: "3"}}
	if err := s.AppendBatch(entries); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	if store.appendN != 3 {
		t.Fatalf("expected 3 Append calls on inner store, got %d", store.appendN)
	}
	if len(metrics.calls) != 1 || metrics.calls[0].entries != 3 {
		t.Fatalf("expected 1 metric with entries=3, got %+v", metrics.calls)
	}
}

func TestInstrumentedStoreAppendBatchStopsOnFirstError(t *testing.T) {
	t.Parallel()
	errSecond := errors.New("write error")
	store := &fakeStoreNoBatch{
		appendFunc: func(n int) error {
			if n == 2 {
				return errSecond
			}
			return nil
		},
	}
	metrics := &fakeMetrics{}
	s := NewInstrumentedStore(store, metrics, "jsonl", "sync")

	entries := []audit.Entry{{ID: "1"}, {ID: "2"}, {ID: "3"}}
	err := s.AppendBatch(entries)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if store.appendN != 2 {
		t.Fatalf("expected 2 Append calls (stop on error), got %d", store.appendN)
	}
	if len(metrics.calls) != 1 || metrics.calls[0].status != "error" {
		t.Fatalf("expected metric with status=error, got %+v", metrics.calls)
	}
	if metrics.calls[0].entries != 3 {
		t.Fatalf("expected metric with entries=3 (full batch size), got %d", metrics.calls[0].entries)
	}
}

func TestInstrumentedStoreQueryDelegates(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	s := NewInstrumentedStore(store, nil, "sqlite", "sync")

	entries, err := s.Query(audit.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "q1" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestInstrumentedStoreStatsDelegates(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	s := NewInstrumentedStore(store, nil, "sqlite", "sync")

	stats, err := s.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalToday != 42 {
		t.Fatalf("expected TotalToday=42, got %d", stats.TotalToday)
	}
}

func TestInstrumentedStoreCloseDelegates(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	s := NewInstrumentedStore(store, nil, "sqlite", "sync")

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestInstrumentedStoreSkipsMetricsWhenRecorderNil(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	s := NewInstrumentedStore(store, nil, "sqlite", "sync")

	// Must not panic.
	if err := s.Append(audit.Entry{ID: "e1"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

func TestInstrumentedStoreSkipsMetricsForZeroEntries(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	metrics := &fakeMetrics{}
	s := NewInstrumentedStore(store, metrics, "sqlite", "sync")

	if err := s.AppendBatch([]audit.Entry{}); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	if len(metrics.calls) != 0 {
		t.Fatalf("expected no metric calls for empty batch, got %d", len(metrics.calls))
	}
}
