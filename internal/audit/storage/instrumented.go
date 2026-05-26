package storage

import (
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

// MetricsRecorder records audit storage metrics.
type MetricsRecorder interface {
	RecordStorageWrite(backend, mode, status string, duration time.Duration, entries int)
}

// InstrumentedStore records storage write metrics for any Store.
type InstrumentedStore struct {
	store   audit.Store
	metrics MetricsRecorder
	backend string
	mode    string
}

// NewInstrumentedStore wraps store with storage write metrics.
func NewInstrumentedStore(store audit.Store, metrics MetricsRecorder, backend, mode string) *InstrumentedStore {
	return &InstrumentedStore{store: store, metrics: metrics, backend: backend, mode: mode}
}

// Append writes entry and records write status and duration.
func (s *InstrumentedStore) Append(entry audit.Entry) error {
	startedAt := time.Now()
	err := s.store.Append(entry)
	s.record(time.Since(startedAt), 1, err)
	return err
}

// AppendBatch writes entries and records write status and duration.
func (s *InstrumentedStore) AppendBatch(entries []audit.Entry) error {
	startedAt := time.Now()
	if store, ok := s.store.(batchAppender); ok {
		err := store.AppendBatch(entries)
		s.record(time.Since(startedAt), len(entries), err)
		return err
	}
	for _, entry := range entries {
		if err := s.store.Append(entry); err != nil {
			s.record(time.Since(startedAt), len(entries), err)
			return err
		}
	}
	s.record(time.Since(startedAt), len(entries), nil)
	return nil
}

// Query delegates to the wrapped store.
func (s *InstrumentedStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	return s.store.Query(filter)
}

// Stats delegates to the wrapped store.
func (s *InstrumentedStore) Stats() (audit.Stats, error) {
	return s.store.Stats()
}

// Close delegates to the wrapped store.
func (s *InstrumentedStore) Close() error {
	return s.store.Close()
}

func (s *InstrumentedStore) record(duration time.Duration, entries int, err error) {
	if s.metrics == nil || entries <= 0 {
		return
	}
	status := "ok"
	if err != nil {
		status = "error"
	}
	s.metrics.RecordStorageWrite(s.backend, s.mode, status, duration, entries)
}
