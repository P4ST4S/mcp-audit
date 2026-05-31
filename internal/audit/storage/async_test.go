package storage

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

func TestAsyncStoreFlushWritesQueuedEntries(t *testing.T) {
	store := newMemoryStore()
	async := NewAsyncStore(store, AsyncConfig{QueueSize: 4, BatchSize: 2, FlushIntervalMS: 10000})
	defer async.Close()

	if err := async.Append(audit.Entry{ID: "1", Method: "tools/list"}); err != nil {
		t.Fatalf("append first entry: %v", err)
	}
	if err := async.Append(audit.Entry{ID: "2", Method: "tools/call"}); err != nil {
		t.Fatalf("append second entry: %v", err)
	}
	if err := async.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	entries := store.entries()
	if len(entries) != 2 {
		t.Fatalf("stored %d entries, want 2", len(entries))
	}
	if entries[0].ID != "1" || entries[1].ID != "2" {
		t.Fatalf("entries stored out of order: %#v", entries)
	}
}

func TestAsyncStoreBackpressureWhenQueueIsFull(t *testing.T) {
	store := newBlockingStore()
	async := NewAsyncStore(store, AsyncConfig{QueueSize: 1, BatchSize: 1, FlushIntervalMS: 10000})
	defer func() {
		store.unblock()
		_ = async.Close()
	}()

	if err := async.Append(audit.Entry{ID: "1"}); err != nil {
		t.Fatalf("append first entry: %v", err)
	}
	store.waitUntilBlocked(t)
	if err := async.Append(audit.Entry{ID: "2"}); err != nil {
		t.Fatalf("append second entry: %v", err)
	}

	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		_ = async.Append(audit.Entry{ID: "3"})
	}()

	select {
	case <-blocked:
		t.Fatal("append completed while async queue was full")
	case <-time.After(50 * time.Millisecond):
	}

	store.unblock()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("append did not unblock after storage resumed")
	}
}

type memoryStore struct {
	mu      sync.Mutex
	records []audit.Entry
}

func newMemoryStore() *memoryStore {
	return &memoryStore{}
}

func (s *memoryStore) Append(entry audit.Entry) error {
	return s.AppendBatch([]audit.Entry{entry})
}

func (s *memoryStore) AppendBatch(entries []audit.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, entries...)
	return nil
}

func (s *memoryStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Entry(nil), s.records...), nil
}

func (s *memoryStore) Stats() (audit.Stats, error) {
	return audit.Stats{}, nil
}

func (s *memoryStore) Close() error {
	return nil
}

func (s *memoryStore) entries() []audit.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Entry(nil), s.records...)
}

type blockingStore struct {
	blocked chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func newBlockingStore() *blockingStore {
	return &blockingStore{
		blocked: make(chan struct{}),
		resume:  make(chan struct{}),
	}
}

func (s *blockingStore) Append(entry audit.Entry) error {
	return s.AppendBatch([]audit.Entry{entry})
}

func (s *blockingStore) AppendBatch(entries []audit.Entry) error {
	s.once.Do(func() {
		close(s.blocked)
	})
	<-s.resume
	return nil
}

func (s *blockingStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	return nil, nil
}

func (s *blockingStore) Stats() (audit.Stats, error) {
	return audit.Stats{}, nil
}

func (s *blockingStore) Close() error {
	return nil
}

func (s *blockingStore) waitUntilBlocked(t *testing.T) {
	t.Helper()
	select {
	case <-s.blocked:
	case <-time.After(time.Second):
		t.Fatal("store did not block")
	}
}

func (s *blockingStore) unblock() {
	select {
	case <-s.resume:
	default:
		close(s.resume)
	}
}

// errorStore retourne une erreur au bout de maxOK appels à AppendBatch.
type errorStore struct {
	mu     sync.Mutex
	calls  int
	maxOK  int
	stored []audit.Entry
}

func (s *errorStore) Append(entry audit.Entry) error {
	return s.AppendBatch([]audit.Entry{entry})
}

func (s *errorStore) AppendBatch(entries []audit.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls > s.maxOK {
		return errors.New("store: write error")
	}
	s.stored = append(s.stored, entries...)
	return nil
}

func (s *errorStore) Query(_ audit.QueryFilter) ([]audit.Entry, error) { return nil, nil }
func (s *errorStore) Stats() (audit.Stats, error)                      { return audit.Stats{}, nil }
func (s *errorStore) Close() error                                      { return nil }

func TestAsyncStoreQueryDelegates(t *testing.T) {
	store := newMemoryStore()
	async := NewAsyncStore(store, AsyncConfig{QueueSize: 4, BatchSize: 2, FlushIntervalMS: 10000})
	defer async.Close()

	if err := async.Append(audit.Entry{ID: "q1", Method: "ping"}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	entries, err := async.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "q1" {
		t.Fatalf("expected entry q1, got %+v", entries)
	}
}

func TestAsyncStoreStatsDelegates(t *testing.T) {
	store := newMemoryStore()
	async := NewAsyncStore(store, AsyncConfig{QueueSize: 4, BatchSize: 2, FlushIntervalMS: 10000})
	defer async.Close()

	if err := async.Append(audit.Entry{ID: "s1", Direction: audit.DirectionClientToServer}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	stats, err := async.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	_ = stats // délégation vérifiée sans panic
}

func TestAsyncStoreAppendReturnsErrorAfterClose(t *testing.T) {
	store := newMemoryStore()
	async := NewAsyncStore(store, AsyncConfig{QueueSize: 4, BatchSize: 2, FlushIntervalMS: 10000})

	if err := async.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err := async.Append(audit.Entry{ID: "late"})
	if err == nil {
		t.Fatal("expected error after Close, got nil")
	}
}

func TestAsyncStorePropagatesWriteError(t *testing.T) {
	store := &errorStore{maxOK: 0} // toute écriture échoue
	async := NewAsyncStore(store, AsyncConfig{QueueSize: 8, BatchSize: 4, FlushIntervalMS: 10000})
	defer func() { _ = async.Close() }()

	if err := async.Append(audit.Entry{ID: "fail-1"}); err != nil {
		t.Fatalf("Append (pre-error): %v", err)
	}

	if err := async.Flush(); err == nil {
		t.Fatal("expected flush to return write error, got nil")
	}

	// Après l'erreur sticky, tout nouvel Append doit échouer.
	err := async.Append(audit.Entry{ID: "fail-2"})
	if err == nil {
		t.Fatal("expected Append to return sticky error, got nil")
	}
}

func TestAsyncStoreFirstErrorIsSticky(t *testing.T) {
	first := errors.New("first write error")
	second := errors.New("second write error")

	store := newMemoryStore()
	async := NewAsyncStore(store, AsyncConfig{QueueSize: 8, BatchSize: 4, FlushIntervalMS: 10000})
	defer func() { _ = async.Close() }()

	// Injecter manuellement deux erreurs successives via setErr.
	async.setErr(first)
	async.setErr(second)

	// Seule la première erreur doit persister.
	got := async.currentErr()
	if got != first {
		t.Fatalf("expected first sticky error %v, got %v", first, got)
	}
}
