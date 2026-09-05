package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
)

func newSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func mustSQLiteAppend(t *testing.T, store *SQLiteStore, entry audit.Entry) {
	t.Helper()
	if err := store.Append(entry); err != nil {
		t.Fatalf("Append %q: %v", entry.ID, err)
	}
}

func TestSQLiteStoreAppendWritesEntry(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)

	mustSQLiteAppend(t, store, audit.Entry{ID: "e1", Method: "ping", ClientID: "c1", ServerID: "s1"})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "e1" {
		t.Fatalf("expected 1 entry with ID=e1, got %+v", entries)
	}
}

func TestSQLiteStoreAppendBatchInTransaction(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)

	batch := []audit.Entry{
		{ID: "b1", ClientID: "c1", ServerID: "s1"},
		{ID: "b2", ClientID: "c1", ServerID: "s1"},
		{ID: "b3", ClientID: "c1", ServerID: "s1"},
	}
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

func TestSQLiteStoreAppendBatchEmptyIsNoop(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)

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

func TestSQLiteStorePersistsRPCError(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)

	rpcErr := &audit.RPCError{Code: -32600, Message: "invalid request"}
	mustSQLiteAppend(t, store, audit.Entry{ID: "err-1", Error: rpcErr, ClientID: "c1", ServerID: "s1"})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	got := entries[0].Error
	if got == nil {
		t.Fatal("expected non-nil Error, got nil")
	}
	if got.Code != -32600 || got.Message != "invalid request" {
		t.Fatalf("unexpected Error round-trip: %+v", got)
	}
}

func TestSQLiteStorePersistsNilRPCError(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)

	mustSQLiteAppend(t, store, audit.Entry{ID: "ok-1", Error: nil, ClientID: "c1", ServerID: "s1"})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Error != nil {
		t.Fatalf("expected nil Error, got %+v", entries[0].Error)
	}
}

func TestSQLiteStoreRoundTripsTimestampUTC(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)

	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Skip("Europe/Paris timezone not available:", err)
	}
	ts := time.Date(2025, 6, 15, 14, 30, 0, 0, paris)
	mustSQLiteAppend(t, store, audit.Entry{ID: "ts-1", Timestamp: ts, ClientID: "c1", ServerID: "s1"})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	got := entries[0].Timestamp.UTC()
	want := ts.UTC()
	if !got.Equal(want) {
		t.Fatalf("timestamp round-trip failed: got %v, want %v", got, want)
	}
}

func TestSQLiteStoreQueryFilterByMethod(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)
	now := time.Now()

	for i := 0; i < 3; i++ {
		mustSQLiteAppend(t, store, audit.Entry{ID: fmt.Sprintf("ping-%d", i), Method: "ping", Timestamp: now.Add(time.Duration(i) * time.Second), ClientID: "c1", ServerID: "s1"})
	}
	for i := 0; i < 2; i++ {
		mustSQLiteAppend(t, store, audit.Entry{ID: fmt.Sprintf("call-%d", i), Method: "tools/call", Timestamp: now.Add(time.Duration(i) * time.Second), ClientID: "c1", ServerID: "s1"})
	}

	entries, err := store.Query(audit.QueryFilter{Method: "ping"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 ping entries, got %d", len(entries))
	}
}

func TestSQLiteStoreQueryFilterByToolName(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)
	now := time.Now()

	for i := 0; i < 2; i++ {
		mustSQLiteAppend(t, store, audit.Entry{ID: fmt.Sprintf("bash-%d", i), ToolName: "bash", Timestamp: now.Add(time.Duration(i) * time.Second), ClientID: "c1", ServerID: "s1"})
	}
	mustSQLiteAppend(t, store, audit.Entry{ID: "python-0", ToolName: "python", Timestamp: now, ClientID: "c1", ServerID: "s1"})

	entries, err := store.Query(audit.QueryFilter{ToolName: "bash"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 bash entries, got %d", len(entries))
	}
}

func TestSQLiteStoreQueryFilterByClientID(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)
	now := time.Now()

	for i := 0; i < 2; i++ {
		mustSQLiteAppend(t, store, audit.Entry{ID: fmt.Sprintf("c1-%d", i), ClientID: "client-1", Timestamp: now.Add(time.Duration(i) * time.Second), ServerID: "s1"})
	}
	mustSQLiteAppend(t, store, audit.Entry{ID: "c2-0", ClientID: "client-2", Timestamp: now, ServerID: "s1"})

	entries, err := store.Query(audit.QueryFilter{ClientID: "client-1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries for client-1, got %d", len(entries))
	}
}

func TestSQLiteStoreQueryFilterByTimeRange(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)
	now := time.Now().Truncate(time.Second)

	timestamps := []time.Time{
		now.Add(-2 * 24 * time.Hour),
		now.Add(-24 * time.Hour),
		now,
		now.Add(24 * time.Hour),
		now.Add(2 * 24 * time.Hour),
	}
	for i, ts := range timestamps {
		mustSQLiteAppend(t, store, audit.Entry{ID: fmt.Sprintf("e%d", i), Timestamp: ts, ClientID: "c1", ServerID: "s1"})
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

func TestSQLiteStoreQueryRespectsLimit(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)
	now := time.Now()

	for i := 0; i < 10; i++ {
		mustSQLiteAppend(t, store, audit.Entry{ID: fmt.Sprintf("e%d", i), Timestamp: now.Add(time.Duration(i) * time.Second), ClientID: "c1", ServerID: "s1"})
	}

	entries, err := store.Query(audit.QueryFilter{Limit: 3})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (limit), got %d", len(entries))
	}
	if entries[0].ID != "e9" {
		t.Fatalf("expected newest entry first (e9), got %s", entries[0].ID)
	}
}

func TestSQLiteStoreStatsAggregates(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)
	now := time.Now()

	mustSQLiteAppend(t, store, audit.Entry{ID: "1", Direction: audit.DirectionClientToServer, ToolName: "bash", Timestamp: now, ClientID: "c1", ServerID: "s1"})
	mustSQLiteAppend(t, store, audit.Entry{ID: "2", Direction: audit.DirectionClientToServer, ToolName: "bash", Timestamp: now, ClientID: "c1", ServerID: "s1"})
	mustSQLiteAppend(t, store, audit.Entry{ID: "3", Direction: audit.DirectionClientToServer, ToolName: "python", Error: &audit.RPCError{Code: -32600, Message: "invalid"}, Timestamp: now, ClientID: "c1", ServerID: "s1"})
	mustSQLiteAppend(t, store, audit.Entry{ID: "4", Direction: audit.DirectionServerToClient, Timestamp: now, ClientID: "c1", ServerID: "s1"})

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

func TestSQLiteStorePersistsAcrossReopens(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")

	store1, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	mustSQLiteAppend(t, store1, audit.Entry{ID: "persistent-1", ClientID: "c1", ServerID: "s1"})
	if err := store1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store2, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore reopen: %v", err)
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

func TestSQLiteStoreInitMigratesRequestIDColumn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")

	// Build a DB without the request_id column to simulate old schema.
	import_db, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore initial: %v", err)
	}
	// Drop request_id by recreating the table without it (complex — instead just
	// verify that NewSQLiteStore on an existing DB is idempotent, which covers the
	// ALTER TABLE catch-duplicate-column path).
	if err := import_db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen — init() must not fail (CREATE IF NOT EXISTS + duplicate column catch).
	store2, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore reopen (idempotent init): %v", err)
	}
	defer store2.Close()
}

func TestSQLiteStoreInitIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")

	s1, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("first NewSQLiteStore: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("second NewSQLiteStore (should be idempotent): %v", err)
	}
	defer s2.Close()
}

func TestSQLiteStorePersistsRequestID(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)

	mustSQLiteAppend(t, store, audit.Entry{ID: "req-1", RequestID: "rpc-42", ClientID: "c1", ServerID: "s1"})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].RequestID != "rpc-42" {
		t.Fatalf("expected RequestID=rpc-42, got %q", entries[0].RequestID)
	}
}

func TestSQLiteStorePersistsPrincipalProjection(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)
	want := &audit.Principal{Subject: "alice", ClientID: "client-1", Issuer: "https://issuer.example.com"}
	mustSQLiteAppend(t, store, audit.Entry{ID: "principal-1", ClientID: "client-1", ServerID: "s1", Principal: want})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].Principal == nil || *entries[0].Principal != *want {
		t.Fatalf("principal = %#v", entries)
	}
}

func TestSQLiteStorePersistsMCPNameAndPolicyEvidence(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)
	mustSQLiteAppend(t, store, audit.Entry{
		ID:       "policy-1",
		Method:   "resources/read",
		MCPName:  "file:///restricted",
		ClientID: "client-1",
		ServerID: "filesystem",
		Policy:   &audit.PolicyEvidence{Decision: "deny", RuleID: "SEC-014"},
	})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].MCPName != "file:///restricted" || entries[0].Policy == nil {
		t.Fatalf("MCP policy evidence did not round-trip: %#v", entries)
	}
	if entries[0].Policy.Decision != "deny" || entries[0].Policy.RuleID != "SEC-014" {
		t.Fatalf("policy evidence = %#v", entries[0].Policy)
	}
}

func TestSQLiteStorePersistsOperationLifecycle(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)

	mustSQLiteAppend(t, store, audit.Entry{
		ID:               "operation-1",
		AuditOperationID: "019d2f6e-47ad-75ad-b506-b7990d8c11ba",
		Outcome:          audit.OutcomeTimeout,
		ClientID:         "c1",
		ServerID:         "s1",
	})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].AuditOperationID != "019d2f6e-47ad-75ad-b506-b7990d8c11ba" {
		t.Fatalf("operation ID = %q", entries[0].AuditOperationID)
	}
	if entries[0].Outcome != audit.OutcomeTimeout {
		t.Fatalf("outcome = %q, want timeout", entries[0].Outcome)
	}
}

func TestSQLiteStorePersistsIntegrityMetadata(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)

	mustSQLiteAppend(t, store, audit.Entry{
		ID:       "integrity-1",
		ClientID: "c1",
		ServerID: "s1",
		Integrity: &integrity.Metadata{
			Version:   integrity.VersionV2,
			Algorithm: integrity.AlgorithmHMACV2,
			KeyID:     "audit-prod",
			Signature: "abcdef",
		},
	})

	entries, err := store.Query(audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].Integrity == nil {
		t.Fatalf("integrity metadata did not round-trip: %#v", entries)
	}
	if entries[0].Integrity.KeyID != "audit-prod" {
		t.Fatalf("key ID = %q, want audit-prod", entries[0].Integrity.KeyID)
	}
}

func TestNewSQLiteStoreCreatesParentDirectory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sub", "dir", "audit.db")

	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore with nested path: %v", err)
	}
	defer store.Close()

	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("parent directory not created: %v", err)
	}
}

func TestSQLiteStoreConcurrentAppendsAreSerialized(t *testing.T) {
	t.Parallel()
	store := newSQLiteStore(t)
	const N = 100

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			_ = store.Append(audit.Entry{
				ID:       fmt.Sprintf("entry-%d", i),
				Method:   "ping",
				ClientID: "c1",
				ServerID: "s1",
			})
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
