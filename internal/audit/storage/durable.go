package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

type durableBatchAppender interface{ AppendBatchDurable([]audit.Entry) error }

// AppendDurable commits an entry with SQLite's FULL synchronous setting.
func (s *SQLiteStore) AppendDurable(entry audit.Entry) error { return s.Append(entry) }

// AppendBatchDurable commits the whole batch with SQLite's FULL synchronous setting.
func (s *SQLiteStore) AppendBatchDurable(entries []audit.Entry) error { return s.AppendBatch(entries) }

// Sync needs no extra barrier because SQLite commits already use synchronous=FULL.
func (s *SQLiteStore) Sync() error { return nil }

// LookupEntry reads a committed record by its unique ID to resolve an uncertain append.
func (s *SQLiteStore) LookupEntry(id string) (audit.Entry, bool, error) {
	var entry audit.Entry
	found := false
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := s.walkEntriesContext(ctx, sqliteEntries+" WHERE id = ?", []any{id}, func(e audit.Entry) { entry, found = e, true })
	return entry, found, err
}

// AppendDurable syncs the new record before any rotation or acknowledgement.
func (s *JSONLStore) AppendDurable(entry audit.Entry) error {
	return s.appendBatch([]audit.Entry{entry}, true)
}

// AppendBatchDurable syncs the complete batch before acknowledging it.
func (s *JSONLStore) AppendBatchDurable(entries []audit.Entry) error {
	return s.appendBatch(entries, true)
}

// LookupEntry checks the complete retained stream and rejects duplicate identities.
func (s *JSONLStore) LookupEntry(id string) (audit.Entry, bool, error) {
	var entry audit.Entry
	count := 0
	err := s.walkEntriesMode(func(e audit.Entry) {
		if e.ID == id {
			entry = e
			count++
		}
	}, true)
	if err == nil && count > 1 {
		err = fmt.Errorf("audit: jsonl: duplicate record identity")
	}
	return entry, count == 1, err
}

// Sync flushes and syncs retained files after an uncertain acknowledgement.
func (s *JSONLStore) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer == nil {
		return fmt.Errorf("audit: jsonl: sync without an open file")
	}
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("audit: jsonl: flush confirmation: %w", err)
	}
	paths, err := s.queryPaths()
	if err != nil {
		return err
	}
	for _, path := range paths {
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("audit: jsonl: open confirmation: %w", err)
		}
		syncErr := s.config.syncFile(file)
		closeErr := file.Close()
		if syncErr != nil {
			return fmt.Errorf("audit: jsonl: sync confirmation: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("audit: jsonl: close confirmation: %w", closeErr)
		}
	}
	return syncDirectory(filepath.Dir(s.path))
}

// LookupEntry delegates identity resolution through the metrics wrapper.
func (s *InstrumentedStore) LookupEntry(id string) (audit.Entry, bool, error) {
	if store, ok := s.store.(audit.EntryLookup); ok {
		return store.LookupEntry(id)
	}
	return audit.Entry{}, false, fmt.Errorf("audit: storage does not support identity lookup")
}

// Sync delegates the durability barrier through the metrics wrapper.
func (s *InstrumentedStore) Sync() error {
	if store, ok := s.store.(audit.Syncer); ok {
		return store.Sync()
	}
	return fmt.Errorf("audit: storage does not support durable confirmation")
}

// AppendDurable records metrics only after the underlying durability barrier.
func (s *InstrumentedStore) AppendDurable(entry audit.Entry) error {
	started := time.Now()
	var err error
	if store, ok := s.store.(audit.DurableAppender); ok {
		err = store.AppendDurable(entry)
	} else {
		err = fmt.Errorf("audit: storage does not support durable appends")
	}
	s.record(time.Since(started), 1, err)
	return err
}

// AppendBatchDurable delegates durable batching without weakening acknowledgement.
func (s *InstrumentedStore) AppendBatchDurable(entries []audit.Entry) error {
	started := time.Now()
	var err error
	if store, ok := s.store.(durableBatchAppender); ok {
		err = store.AppendBatchDurable(entries)
	} else {
		err = fmt.Errorf("audit: storage does not support durable batches")
	}
	s.record(time.Since(started), len(entries), err)
	return err
}

// AppendDurable waits for a disk acknowledgement instead of just queue acceptance.
func (s *AsyncStore) AppendDurable(entry audit.Entry) error {
	if !s.durable {
		return fmt.Errorf("audit: async: durable batching is not enabled")
	}
	if err := s.currentErr(); err != nil {
		<-s.done
		s.closeMu.RLock()
		defer s.closeMu.RUnlock()
		if s.closed {
			return fmt.Errorf("audit: async: append after close: %w", err)
		}
		if store, ok := s.store.(audit.DurableAppender); ok {
			return store.AppendDurable(entry)
		}
		return err
	}
	if err := s.Append(entry); err != nil {
		return err
	}
	return s.Flush()
}

// LookupEntry resolves records through the queue without trusting an enqueue ack.
func (s *AsyncStore) LookupEntry(id string) (audit.Entry, bool, error) {
	if s.currentErr() != nil {
		<-s.done
	}
	if store, ok := s.store.(audit.EntryLookup); ok {
		return store.LookupEntry(id)
	}
	return audit.Entry{}, false, fmt.Errorf("audit: storage does not support identity lookup")
}

// Sync confirms already-written records, including after a worker has stopped.
func (s *AsyncStore) Sync() error {
	if s.currentErr() != nil {
		<-s.done
	} else if err := s.Flush(); err != nil {
		return err
	}
	if store, ok := s.store.(audit.Syncer); ok {
		return store.Sync()
	}
	return fmt.Errorf("audit: storage does not support durable confirmation")
}
