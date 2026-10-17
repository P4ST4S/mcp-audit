package storage

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
)

func TestSQLiteWriterCommitsWhileReaderIsOpen(t *testing.T) {
	store := newSQLiteStore(t)
	if err := store.Append(audit.Entry{ID: "seed"}); err != nil {
		t.Fatal(err)
	}
	rows, err := store.db.Query("SELECT id FROM audit_entries")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("missing seed")
	}
	done := make(chan error, 1)
	go func() { done <- store.Append(audit.Entry{ID: "during-read"}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write during dashboard read: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer blocked behind reader")
	}
}

func TestSQLiteConnectionPragmasAndRecoveryAfterBusyCommit(t *testing.T) {
	store := newSQLiteStore(t)
	first, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, conn := range []*sql.Conn{first, second} {
		var busy, synchronous int
		if err := conn.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&busy); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRowContext(context.Background(), "PRAGMA synchronous").Scan(&synchronous); err != nil {
			t.Fatal(err)
		}
		if busy != 1000 || synchronous != 2 {
			t.Fatalf("pragmas busy=%d synchronous=%d", busy, synchronous)
		}
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	store.db.SetMaxIdleConns(0)
	store.db.SetMaxIdleConns(2)
	if _, err := store.db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(audit.Entry{ID: "seed"}); err != nil {
		t.Fatal(err)
	}
	rows, err := store.db.Query("SELECT id FROM audit_entries")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("no seed")
	}
	if err := store.Append(audit.Entry{ID: "busy"}); err == nil {
		t.Fatal("commit should fail behind DELETE-mode reader")
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(audit.Entry{ID: "recovered"}); err != nil {
		t.Fatalf("poisoned connection after failed commit: %v", err)
	}
	if _, found, err := store.LookupEntry("busy"); err != nil || found {
		t.Fatalf("failed commit retained: found=%v err=%v", found, err)
	}
}

func TestJSONLDurableSyncFailureRollsBackAndRejectsIncompleteTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	failed := false
	store, err := NewJSONLStoreWithConfig(path, JSONLConfig{Durable: true, syncFile: func(f *os.File) error {
		if !failed {
			failed = true
			return errors.New("injected sync failure")
		}
		return f.Sync()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Append(audit.Entry{ID: "record"}); err == nil {
		t.Fatal("sync failure acknowledged")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) != 0 {
		t.Fatalf("failed sync retained bytes: %q %v", raw, err)
	}
	if err := store.Append(audit.Entry{ID: "record"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.file.WriteString(`{"id":"partial`); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(audit.Entry{ID: "next"}); err == nil {
		t.Fatal("accepted incomplete existing tail")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("damaged evidence modified")
	}
	if _, _, err := store.LookupEntry("record"); err == nil {
		t.Fatal("lookup ignored malformed evidence")
	}
}

type transientDurableStore struct {
	*JSONLStore
	failed bool
}

func (s *transientDurableStore) AppendBatchDurable(entries []audit.Entry) error {
	if !s.failed {
		s.failed = true
		return errors.New("injected transient batch failure")
	}
	return s.JSONLStore.AppendBatchDurable(entries)
}

func TestDurableAsyncFinalizeRecoversAndDoesNotDuplicate(t *testing.T) {
	underlying := &transientDurableStore{JSONLStore: newJSONLStore(t)}
	async := NewAsyncStore(underlying, AsyncConfig{Durable: true})
	logger := audit.NewLogger(audit.LoggerConfig{Store: async, Durable: true})
	op, err := audit.NewOperation(logger, audit.Entry{Method: "tools/call"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := op.Finalize(audit.Completion{Outcome: audit.OutcomeSuccess}); err != nil {
		t.Fatal(err)
	}
	entries, err := underlying.Query(audit.QueryFilter{})
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	if err := async.Close(); err == nil {
		t.Fatal("worker error must remain observable on close")
	}
	if err := async.Close(); err == nil {
		t.Fatal("repeated close lost error")
	}
	if err := async.AppendDurable(audit.Entry{ID: "late"}); err == nil {
		t.Fatal("durable append after close accepted")
	}
}

func (s *blockingStore) AppendBatchDurable(entries []audit.Entry) error {
	return s.AppendBatch(entries)
}

func TestDurableAsyncAcknowledgementWaitsForStorage(t *testing.T) {
	store := newBlockingStore()
	async := NewAsyncStore(store, AsyncConfig{Durable: true})
	defer async.Close()
	done := make(chan error, 1)
	go func() { done <- async.AppendDurable(audit.Entry{ID: "blocked"}) }()
	store.waitUntilBlocked(t)
	select {
	case err := <-done:
		t.Fatalf("ack before storage: %v", err)
	default:
	}
	store.unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("durable ack stuck")
	}
}

func TestAsyncConcurrentCloseAndAppend(t *testing.T) {
	for iteration := 0; iteration < 50; iteration++ {
		async := NewAsyncStore(newMemoryStore(), AsyncConfig{QueueSize: 1, BatchSize: 1})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = async.Append(audit.Entry{ID: "concurrent"})
			}
		}()
		go func() { defer wg.Done(); _ = async.Close() }()
		wg.Wait()
	}
}

type uncertainAckStore struct {
	audit.Store
	audit.DurableAppender
	audit.EntryLookup
	audit.Syncer
	writes int
}

func (s *uncertainAckStore) AppendDurable(entry audit.Entry) error {
	s.writes++
	if err := s.DurableAppender.AppendDurable(entry); err != nil {
		return err
	}
	return errors.New("injected lost acknowledgement after storage barrier")
}

func TestFinalizeReconcilesSignedCommittedRecordAcrossBackends(t *testing.T) {
	for _, backend := range []string{"jsonl", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var base audit.Store
			if backend == "jsonl" {
				base = newJSONLStore(t)
			} else {
				base = newSQLiteStore(t)
			}
			uncertain := &uncertainAckStore{Store: base, DurableAppender: base.(audit.DurableAppender), EntryLookup: base.(audit.EntryLookup), Syncer: base.(audit.Syncer)}
			logger := audit.NewLogger(audit.LoggerConfig{Store: NewInstrumentedStore(uncertain, nil, backend, "sync"), Durable: true, Signer: audit.NewSigner("storage retry test secret"), IntegritySigner: integrity.NewSigner("storage retry test secret", "test")})
			entry := audit.Entry{Method: "tools/call", Timestamp: time.Date(2026, 10, 17, 12, 0, 0, 123, time.FixedZone("offset", 7200))}
			op, err := audit.NewOperation(logger, entry, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := op.Finalize(audit.Completion{Outcome: audit.OutcomeSuccess}); err != nil {
				t.Fatal(err)
			}
			entries, err := base.Query(audit.QueryFilter{})
			if err != nil || len(entries) != 1 || uncertain.writes != 1 {
				t.Fatalf("entries=%v writes=%d error=%v", entries, uncertain.writes, err)
			}
			if err := integrity.NewVerifier(map[string]string{"test": "storage retry test secret"}).Verify(audit.IntegrityEntryV2(entries[0]), entries[0].Integrity); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type partialFileWriter struct{ file *os.File }

func (w partialFileWriter) Write(p []byte) (int, error) {
	n, err := w.file.Write(p[:len(p)/2])
	if err != nil {
		return n, err
	}
	return n, errors.New("injected partial write")
}

func TestJSONLRollsBackPartialWriteAndCanRetry(t *testing.T) {
	store := newJSONLStore(t)
	if err := store.Append(audit.Entry{ID: "before"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	store.writer = bufio.NewWriterSize(partialFileWriter{store.file}, 16)
	entry := audit.Entry{ID: "retry", Method: "tools/call"}
	if err := store.Append(entry); err == nil {
		t.Fatal("expected partial-write error")
	}
	after, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("partial record retained: %q", after)
	}
	if err := store.Append(entry); err != nil {
		t.Fatalf("retry: %v", err)
	}
	entries, err := store.Query(audit.QueryFilter{})
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries=%+v error=%v", entries, err)
	}
}
