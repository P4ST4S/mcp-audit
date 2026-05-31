package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

func newJSONLStore(t *testing.T) *JSONLStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func mustAppend(t *testing.T, store *JSONLStore, entry audit.Entry) {
	t.Helper()
	if err := store.Append(entry); err != nil {
		t.Fatalf("Append %q: %v", entry.ID, err)
	}
}

func TestJSONLStoreAppendWritesEntry(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)

	mustAppend(t, store, audit.Entry{ID: "e1", Method: "ping"})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "e1" {
		t.Fatalf("expected 1 entry with ID=e1, got %+v", entries)
	}
}

func TestJSONLStoreAppendBatchWritesMultiple(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)

	batch := []audit.Entry{{ID: "1"}, {ID: "2"}, {ID: "3"}}
	if err := store.AppendBatch(batch); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	entries, err := store.Query(audit.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

func TestJSONLStoreAppendBatchEmptyIsNoop(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)

	if err := store.AppendBatch([]audit.Entry{}); err != nil {
		t.Fatalf("AppendBatch([]): %v", err)
	}

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries after empty batch, got %d", len(entries))
	}
}

func TestJSONLStoreQueryReturnsAppendedEntries(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)
	now := time.Now()

	for i := 0; i < 5; i++ {
		mustAppend(t, store, audit.Entry{
			ID:        fmt.Sprintf("e%d", i),
			Method:    "tools/list",
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
}

func TestJSONLStoreQueryFilterByMethod(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)
	now := time.Now()

	for i := 0; i < 3; i++ {
		mustAppend(t, store, audit.Entry{ID: fmt.Sprintf("ping-%d", i), Method: "ping", Timestamp: now.Add(time.Duration(i) * time.Second)})
	}
	for i := 0; i < 2; i++ {
		mustAppend(t, store, audit.Entry{ID: fmt.Sprintf("call-%d", i), Method: "tools/call", Timestamp: now.Add(time.Duration(i) * time.Second)})
	}

	entries, err := store.Query(audit.QueryFilter{Method: "ping"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 ping entries, got %d", len(entries))
	}
}

func TestJSONLStoreQueryFilterByToolName(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)
	now := time.Now()

	for i := 0; i < 2; i++ {
		mustAppend(t, store, audit.Entry{ID: fmt.Sprintf("bash-%d", i), ToolName: "bash", Timestamp: now.Add(time.Duration(i) * time.Second)})
	}
	mustAppend(t, store, audit.Entry{ID: "python-0", ToolName: "python", Timestamp: now})

	entries, err := store.Query(audit.QueryFilter{ToolName: "bash"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 bash entries, got %d", len(entries))
	}
}

func TestJSONLStoreQueryFilterByClientID(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)
	now := time.Now()

	for i := 0; i < 2; i++ {
		mustAppend(t, store, audit.Entry{ID: fmt.Sprintf("c1-%d", i), ClientID: "client-1", Timestamp: now.Add(time.Duration(i) * time.Second)})
	}
	mustAppend(t, store, audit.Entry{ID: "c2-0", ClientID: "client-2", Timestamp: now})

	entries, err := store.Query(audit.QueryFilter{ClientID: "client-1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries for client-1, got %d", len(entries))
	}
}

func TestJSONLStoreQueryFilterByTimeRange(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)
	now := time.Now().Truncate(time.Second)

	timestamps := []time.Time{
		now.Add(-2 * 24 * time.Hour),
		now.Add(-24 * time.Hour),
		now,
		now.Add(24 * time.Hour),
		now.Add(2 * 24 * time.Hour),
	}
	for i, ts := range timestamps {
		mustAppend(t, store, audit.Entry{ID: fmt.Sprintf("e%d", i), Timestamp: ts})
	}

	from := now.Add(-24 * time.Hour)
	to := now.Add(24 * time.Hour)
	entries, err := store.Query(audit.QueryFilter{From: from, To: to, Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries in range [T-1d, T+1d], got %d", len(entries))
	}
}

func TestJSONLStoreQueryRespectsLimit(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)
	now := time.Now()

	for i := 0; i < 10; i++ {
		mustAppend(t, store, audit.Entry{ID: fmt.Sprintf("e%d", i), Timestamp: now.Add(time.Duration(i) * time.Second)})
	}

	entries, err := store.Query(audit.QueryFilter{Limit: 3})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (limit), got %d", len(entries))
	}
	// LimitNewest returns newest first.
	if entries[0].ID != "e9" {
		t.Fatalf("expected newest entry first (e9), got %s", entries[0].ID)
	}
}

func TestJSONLStoreQuerySkipsInvalidJSONLines(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	store, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore: %v", err)
	}
	defer store.Close()

	mustAppend(t, store, audit.Entry{ID: "valid-1"})
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Inject a corrupt line in the middle.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for corrupt injection: %v", err)
	}
	if _, err := fmt.Fprintln(f, `{INVALID JSON}`); err != nil {
		t.Fatalf("write corrupt line: %v", err)
	}
	_ = f.Close()

	store2, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore reopen: %v", err)
	}
	defer store2.Close()

	mustAppend(t, store2, audit.Entry{ID: "valid-2"})

	entries, err := store2.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 valid entries (skipping corrupt line), got %d", len(entries))
	}
}

func TestJSONLStoreStatsAggregates(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)
	now := time.Now()

	mustAppend(t, store, audit.Entry{ID: "1", Direction: audit.DirectionClientToServer, ToolName: "bash", Timestamp: now})
	mustAppend(t, store, audit.Entry{ID: "2", Direction: audit.DirectionClientToServer, ToolName: "bash", Timestamp: now})
	mustAppend(t, store, audit.Entry{ID: "3", Direction: audit.DirectionClientToServer, ToolName: "python", Error: &audit.RPCError{Code: -32600, Message: "invalid"}, Timestamp: now})
	mustAppend(t, store, audit.Entry{ID: "4", Direction: audit.DirectionServerToClient, Timestamp: now})

	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalToday != 3 {
		t.Fatalf("expected TotalToday=3, got %d", stats.TotalToday)
	}
	wantErrorRate := 1.0 / 3.0
	if stats.ErrorRate < wantErrorRate-0.001 || stats.ErrorRate > wantErrorRate+0.001 {
		t.Fatalf("expected ErrorRate~%.3f, got %.3f", wantErrorRate, stats.ErrorRate)
	}
	if len(stats.TopTools) == 0 || stats.TopTools[0].Name != "bash" {
		t.Fatalf("expected top tool=bash, got %+v", stats.TopTools)
	}
}

func TestJSONLStorePersistsAcrossReopens(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	store1, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore: %v", err)
	}
	mustAppend(t, store1, audit.Entry{ID: "persistent-1"})
	if err := store1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store2, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore reopen: %v", err)
	}
	defer store2.Close()

	entries, err := store2.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query after reopen: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "persistent-1" {
		t.Fatalf("expected entry persistent-1 after reopen, got %+v", entries)
	}
}

func TestNewJSONLStoreCreatesParentDirectory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sub", "dir", "audit.jsonl")

	store, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore with nested path: %v", err)
	}
	defer store.Close()

	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("parent directory not created: %v", err)
	}
}

func TestJSONLStoreCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)

	if err := store.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close must not panic.
	_ = store.Close()
}

func TestJSONLStoreConcurrentAppendsAreSerialized(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)
	const N = 100

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			_ = store.Append(audit.Entry{ID: fmt.Sprintf("entry-%d", i), Method: "ping"})
		}(i)
	}
	wg.Wait()

	entries, err := store.Query(audit.QueryFilter{Limit: N + 10})
	if err != nil {
		t.Fatalf("Query after concurrent appends: %v", err)
	}
	if len(entries) != N {
		t.Fatalf("expected %d entries after concurrent appends, got %d", N, len(entries))
	}
}

func TestJSONLStoreAppendAfterQueryWritesToEnd(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)

	mustAppend(t, store, audit.Entry{ID: "before-query"})
	_, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	mustAppend(t, store, audit.Entry{ID: "after-query"})

	entries, err := store.Query(audit.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query after second append: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after query+append cycle, got %d", len(entries))
	}
}
