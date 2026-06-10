package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

const archiveTimestampLayout = "20060102T150405Z"

var archiveSuffixPattern = regexp.MustCompile(`^\d{8}T\d{6}Z(?:\.\d+)?$`)

// JSONLConfig configures JSONL audit storage.
type JSONLConfig struct {
	MaxSizeBytes int64
	MaxFiles     int
	Log          *slog.Logger

	now    func() time.Time
	rename func(oldPath, newPath string) error
}

// JSONLStore appends audit entries as one JSON document per line.
type JSONLStore struct {
	mu     sync.Mutex
	path   string
	config JSONLConfig
	file   *os.File
	writer *bufio.Writer
}

// NewJSONLStore opens path for append-only JSONL storage.
func NewJSONLStore(path string) (*JSONLStore, error) {
	return NewJSONLStoreWithConfig(path, JSONLConfig{})
}

// NewJSONLStoreWithConfig opens path for append-only JSONL storage.
func NewJSONLStoreWithConfig(path string, config JSONLConfig) (*JSONLStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return nil, fmt.Errorf("audit: jsonl: create directory: %w", err)
	}
	if config.MaxSizeBytes < 0 {
		config.MaxSizeBytes = 0
	}
	if config.MaxFiles < 0 {
		config.MaxFiles = 0
	}
	if config.now == nil {
		config.now = time.Now
	}
	if config.rename == nil {
		config.rename = os.Rename
	}
	store := &JSONLStore{path: path, config: config}
	if err := store.openActive(); err != nil {
		return nil, err
	}
	return store, nil
}

// Append writes entry to the JSONL file.
func (s *JSONLStore) Append(entry audit.Entry) error {
	return s.AppendBatch([]audit.Entry{entry})
}

// AppendBatch writes entries to the JSONL file with a single flush.
func (s *JSONLStore) AppendBatch(entries []audit.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	encoder := json.NewEncoder(s.writer)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			return fmt.Errorf("audit: jsonl: encode: %w", err)
		}
	}
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("audit: jsonl: flush: %w", err)
	}
	s.rotateIfNeeded()
	return nil
}

// Query returns recent entries matching filter.
func (s *JSONLStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writer.Flush(); err != nil {
		return nil, fmt.Errorf("audit: jsonl: flush before query: %w", err)
	}

	var entries []audit.Entry
	paths, err := s.queryPaths()
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("audit: jsonl: open query file: %w", err)
		}
		if err := scanJSONL(file, filter, &entries); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("audit: jsonl: close query file: %w", err)
		}
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
	s.file = nil
	s.writer = nil
	return flushErr
}

func (s *JSONLStore) openActive() error {
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("audit: jsonl: open: %w", err)
	}
	s.file = file
	s.writer = bufio.NewWriter(file)
	return nil
}

func (s *JSONLStore) rotateIfNeeded() {
	if s.config.MaxSizeBytes <= 0 || s.file == nil {
		return
	}
	info, err := s.file.Stat()
	if err != nil {
		s.logRotationError("stat active file", err)
		return
	}
	if info.Size() < s.config.MaxSizeBytes {
		return
	}
	if err := s.rotate(); err != nil {
		s.logRotationError("rotate active file", err)
	}
}

func (s *JSONLStore) rotate() error {
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("flush before rotation: %w", err)
	}
	if err := s.file.Close(); err != nil {
		return fmt.Errorf("close before rotation: %w", err)
	}
	s.file = nil
	s.writer = nil

	archivePath := s.nextArchivePath()
	if err := s.config.rename(s.path, archivePath); err != nil {
		if reopenErr := s.openActive(); reopenErr != nil {
			return fmt.Errorf("rename: %w; reopen active: %v", err, reopenErr)
		}
		return fmt.Errorf("rename: %w", err)
	}
	if err := s.openActive(); err != nil {
		return err
	}
	s.applyRetention()
	return nil
}

func (s *JSONLStore) nextArchivePath() string {
	base := fmt.Sprintf("%s.%s", s.path, s.config.now().UTC().Format(archiveTimestampLayout))
	path := base
	for i := 1; ; i++ {
		if _, err := os.Stat(path); err != nil {
			return path
		}
		path = fmt.Sprintf("%s.%d", base, i)
	}
}

func (s *JSONLStore) queryPaths() ([]string, error) {
	archives, err := s.archivePaths()
	if err != nil {
		return nil, err
	}
	return append(archives, s.path), nil
}

func (s *JSONLStore) archivePaths() ([]string, error) {
	dir := filepath.Dir(s.path)
	base := filepath.Base(s.path) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("audit: jsonl: read archive directory: %w", err)
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		suffix := strings.TrimPrefix(name, base)
		if !archiveSuffixPattern.MatchString(suffix) {
			continue
		}
		paths = append(paths, filepath.Join(dir, name))
	}
	sort.Strings(paths)
	return paths, nil
}

func (s *JSONLStore) applyRetention() {
	if s.config.MaxFiles <= 0 {
		return
	}
	archives, err := s.archivePaths()
	if err != nil {
		s.logRotationError("list archives for retention", err)
		return
	}
	if len(archives) <= s.config.MaxFiles {
		return
	}
	for _, path := range archives[:len(archives)-s.config.MaxFiles] {
		if err := os.Remove(path); err != nil {
			s.logRotationError("remove archive for retention", err)
		}
	}
}

func (s *JSONLStore) logRotationError(operation string, err error) {
	if s.config.Log != nil {
		s.config.Log.Warn("jsonl rotation failed", "operation", operation, "error", err)
	}
}

func scanJSONL(file *os.File, filter audit.QueryFilter, entries *[]audit.Entry) error {
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var entry audit.Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if audit.MatchFilter(entry, filter) {
			*entries = append(*entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("audit: jsonl: scan: %w", err)
	}
	return nil
}
