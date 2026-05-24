package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

// JSONLStore appends audit entries as one JSON document per line.
type JSONLStore struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
}

// NewJSONLStore opens path for append-only JSONL storage.
func NewJSONLStore(path string) (*JSONLStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return nil, fmt.Errorf("audit: jsonl: create directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: jsonl: open: %w", err)
	}
	return &JSONLStore{file: file, writer: bufio.NewWriter(file)}, nil
}

// Append writes entry to the JSONL file.
func (s *JSONLStore) Append(entry audit.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := json.NewEncoder(s.writer).Encode(entry); err != nil {
		return fmt.Errorf("audit: jsonl: encode: %w", err)
	}
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("audit: jsonl: flush: %w", err)
	}
	return nil
}

// Query returns recent entries matching filter.
func (s *JSONLStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writer.Flush(); err != nil {
		return nil, fmt.Errorf("audit: jsonl: flush before query: %w", err)
	}
	if _, err := s.file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("audit: jsonl: seek: %w", err)
	}

	scanner := bufio.NewScanner(s.file)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var entries []audit.Entry
	for scanner.Scan() {
		var entry audit.Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if audit.MatchFilter(entry, filter) {
			entries = append(entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: jsonl: scan: %w", err)
	}
	if _, err := s.file.Seek(0, 2); err != nil {
		return nil, fmt.Errorf("audit: jsonl: seek end: %w", err)
	}

	return audit.LimitNewest(entries, filter.Limit), nil
}

// Stats returns aggregate dashboard statistics.
func (s *JSONLStore) Stats() (audit.Stats, error) {
	entries, err := s.Query(audit.QueryFilter{Limit: 10000})
	if err != nil {
		return audit.Stats{}, fmt.Errorf("audit: jsonl: stats query: %w", err)
	}
	return audit.BuildStats(entries), nil
}

// Close flushes and closes the JSONL file.
func (s *JSONLStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var flushErr error
	if s.writer != nil {
		flushErr = s.writer.Flush()
	}
	if s.file == nil {
		return flushErr
	}
	if err := s.file.Close(); err != nil {
		return fmt.Errorf("audit: jsonl: close: %w", err)
	}
	return flushErr
}
