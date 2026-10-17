package storage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/gowebpki/jcs"
)

const archiveTimestampLayout = "20060102T150405Z"

var archiveSuffixPattern = regexp.MustCompile(`^\d{8}T\d{6}Z(?:\.\d+)?$`)

// JSONLConfig configures JSONL audit storage.
type JSONLConfig struct {
	MaxSizeBytes int64
	MaxFiles     int
	Interval     string
	MaxAgeDays   int
	Log          *slog.Logger
	Durable      bool

	now      func() time.Time
	rename   func(oldPath, newPath string) error
	syncFile func(*os.File) error
}

// JSONLStore appends audit entries as one JSON document per line.
type JSONLStore struct {
	mu             sync.Mutex
	path           string
	config         JSONLConfig
	file           *os.File
	writer         *bufio.Writer
	nextTimeCutoff time.Time
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
	if config.MaxAgeDays < 0 {
		config.MaxAgeDays = 0
	}
	if config.now == nil {
		config.now = time.Now
	}
	if config.rename == nil {
		config.rename = os.Rename
	}
	if config.syncFile == nil {
		config.syncFile = (*os.File).Sync
	}
	store := &JSONLStore{path: path, config: config}
	if config.Interval != "" {
		store.nextTimeCutoff = nextRotationCutoff(config.now(), config.Interval)
	}
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
	return s.appendBatch(entries, s.config.Durable)
}

func (s *JSONLStore) appendBatch(entries []audit.Entry, durable bool) error {
	if len(entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return fmt.Errorf("audit: jsonl: append without an open file")
	}

	info, err := s.file.Stat()
	if err != nil {
		return fmt.Errorf("audit: jsonl: stat before append: %w", err)
	}
	start := info.Size()
	if durable && start > 0 {
		var tail [1]byte
		if _, err := s.file.ReadAt(tail[:], start-1); err != nil {
			return fmt.Errorf("audit: jsonl: read tail: %w", err)
		}
		if tail[0] != '\n' {
			return fmt.Errorf("audit: jsonl: incomplete existing record; repair evidence before appending")
		}
	}
	activeWasEmpty := start == 0
	rollback := func(cause error) error {
		// Reset clears bufio's sticky error only after discarding the failed batch.
		if err := s.file.Truncate(start); err != nil {
			return errors.Join(cause, fmt.Errorf("audit: jsonl: rollback partial append: %w", err))
		}
		s.writer.Reset(s.file)
		if durable {
			if err := s.config.syncFile(s.file); err != nil {
				return errors.Join(cause, fmt.Errorf("audit: jsonl: sync rollback: %w", err))
			}
		}
		return cause
	}
	encoder := json.NewEncoder(s.writer)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			return rollback(fmt.Errorf("audit: jsonl: encode: %w", err))
		}
	}
	if err := s.writer.Flush(); err != nil {
		return rollback(fmt.Errorf("audit: jsonl: flush: %w", err))
	}
	if durable {
		if err := s.config.syncFile(s.file); err != nil {
			return rollback(fmt.Errorf("audit: jsonl: sync: %w", err))
		}
	}
	s.rotateIfNeeded(activeWasEmpty)
	if durable {
		return syncDirectory(filepath.Dir(s.path))
	}
	return nil
}

// Query returns recent entries matching filter.
func (s *JSONLStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	var entries []audit.Entry
	err := s.walkEntries(func(entry audit.Entry) {
		if audit.MatchFilter(entry, filter) {
			entries = append(entries, entry)
		}
	})
	if err != nil {
		return nil, err
	}
	return audit.LimitNewest(entries, filter.Limit), nil
}

func (s *JSONLStore) walkEntries(visit func(audit.Entry)) error {
	return s.walkEntriesMode(visit, false)
}

func (s *JSONLStore) walkEntriesMode(visit func(audit.Entry), strict bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer == nil {
		return fmt.Errorf("audit: jsonl: query without an open file")
	}

	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("audit: jsonl: flush before query: %w", err)
	}

	paths, err := s.queryPaths()
	if err != nil {
		return err
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("audit: jsonl: open query file: %w", err)
		}
		if err := scanJSONLMode(file, visit, strict); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("audit: jsonl: close query file: %w", err)
		}
	}

	return nil
}

// Stats returns aggregate dashboard statistics.
func (s *JSONLStore) Stats() (audit.Stats, error) {
	stats := audit.NewStatsAccumulator(time.Now())
	if err := s.walkEntries(stats.Add); err != nil {
		return audit.Stats{}, fmt.Errorf("audit: jsonl: stats query: %w", err)
	}
	return stats.Stats(), nil
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

func (s *JSONLStore) activeWasEmpty() bool {
	if s.file == nil {
		return true
	}
	info, err := s.file.Stat()
	if err != nil {
		s.logRotationError("stat active file before append", err)
		return false
	}
	return info.Size() == 0
}

func (s *JSONLStore) rotateIfNeeded(activeWasEmptyBeforeAppend bool) {
	if s.file == nil {
		return
	}
	info, err := s.file.Stat()
	if err != nil {
		s.logRotationError("stat active file", err)
		return
	}
	now := s.config.now()
	sizeTriggered := s.config.MaxSizeBytes > 0 && info.Size() >= s.config.MaxSizeBytes
	timeTriggered := s.timeRotationDue(now)
	advanceTimeCutoff := timeTriggered
	if timeTriggered && activeWasEmptyBeforeAppend {
		timeTriggered = false
		if !sizeTriggered {
			s.nextTimeCutoff = nextRotationCutoff(now, s.config.Interval)
		}
	}
	if !sizeTriggered && !timeTriggered {
		return
	}
	if err := s.rotate(now); err != nil {
		s.logRotationError("rotate active file", err)
		return
	}
	if advanceTimeCutoff {
		s.nextTimeCutoff = nextRotationCutoff(now, s.config.Interval)
	}
}

func (s *JSONLStore) timeRotationDue(now time.Time) bool {
	if s.nextTimeCutoff.IsZero() {
		return false
	}
	return !now.UTC().Before(s.nextTimeCutoff)
}

func (s *JSONLStore) rotate(now time.Time) error {
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("flush before rotation: %w", err)
	}
	if err := s.file.Close(); err != nil {
		return fmt.Errorf("close before rotation: %w", err)
	}
	s.file = nil
	s.writer = nil

	archivePath := s.nextArchivePath(now)
	if err := s.config.rename(s.path, archivePath); err != nil {
		if reopenErr := s.openActive(); reopenErr != nil {
			return fmt.Errorf("rename: %w; reopen active: %v", err, reopenErr)
		}
		return fmt.Errorf("rename: %w", err)
	}
	if err := s.openActive(); err != nil {
		return err
	}
	s.applyRetention(now)
	return nil
}

func (s *JSONLStore) nextArchivePath(now time.Time) string {
	base := fmt.Sprintf("%s.%s", s.path, now.UTC().Format(archiveTimestampLayout))
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

func (s *JSONLStore) applyRetention(now time.Time) {
	if s.config.MaxAgeDays <= 0 && s.config.MaxFiles <= 0 {
		return
	}
	if s.config.MaxAgeDays > 0 {
		archives, err := s.archivePaths()
		if err != nil {
			s.logRotationError("list archives for age retention", err)
			return
		}
		cutoff := now.UTC().Add(-time.Duration(s.config.MaxAgeDays) * 24 * time.Hour)
		for _, path := range archives {
			rotationTime, ok := archiveRotationTime(s.path, path)
			if !ok || !rotationTime.Before(cutoff) {
				continue
			}
			if err := os.Remove(path); err != nil {
				s.logRotationError("remove archive for age retention", err)
			}
		}
	}
	if s.config.MaxFiles <= 0 {
		return
	}
	archives, err := s.archivePaths()
	if err != nil {
		s.logRotationError("list archives for file retention", err)
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

func nextRotationCutoff(now time.Time, interval string) time.Time {
	now = now.UTC()
	switch strings.ToLower(interval) {
	case "hourly":
		return now.Truncate(time.Hour).Add(time.Hour)
	case "daily":
		y, m, d := now.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
	default:
		return time.Time{}
	}
}

func archiveRotationTime(activePath, archivePath string) (time.Time, bool) {
	base := filepath.Base(activePath) + "."
	name := filepath.Base(archivePath)
	if !strings.HasPrefix(name, base) {
		return time.Time{}, false
	}
	suffix := strings.TrimPrefix(name, base)
	if !archiveSuffixPattern.MatchString(suffix) {
		return time.Time{}, false
	}
	timestamp := suffix
	if dot := strings.IndexByte(timestamp, '.'); dot >= 0 {
		timestamp = timestamp[:dot]
	}
	rotationTime, err := time.Parse(archiveTimestampLayout, timestamp)
	if err != nil {
		return time.Time{}, false
	}
	return rotationTime, true
}

func (s *JSONLStore) logRotationError(operation string, err error) {
	if s.config.Log != nil {
		s.config.Log.Warn("jsonl rotation failed", "operation", operation, "error", err)
	}
}

func scanJSONL(file *os.File, visit func(audit.Entry)) error {
	return scanJSONLMode(file, visit, false)
}

func scanJSONLMode(file *os.File, visit func(audit.Entry), strict bool) error {
	if strict {
		info, err := file.Stat()
		if err != nil {
			return fmt.Errorf("audit: jsonl: stat evidence: %w", err)
		}
		if info.Size() > 0 {
			var tail [1]byte
			if _, err := file.ReadAt(tail[:], info.Size()-1); err != nil {
				return fmt.Errorf("audit: jsonl: read evidence tail: %w", err)
			}
			if tail[0] != '\n' {
				return fmt.Errorf("audit: jsonl: incomplete evidence during identity lookup")
			}
		}
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		if strict {
			if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
				continue
			}
			if _, err := jcs.Transform(scanner.Bytes()); err != nil {
				return fmt.Errorf("audit: jsonl: ambiguous evidence during identity lookup: %w", err)
			}
		}
		var entry audit.Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			if strict {
				return fmt.Errorf("audit: jsonl: invalid evidence during identity lookup: %w", err)
			}
			continue
		}
		visit(entry)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("audit: jsonl: scan: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	// Windows file Sync does not provide the Unix directory-entry durability barrier.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("audit: jsonl: open directory for sync: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}
