package storage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func newRotatingJSONLStore(t *testing.T, config JSONLConfig) (*JSONLStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := NewJSONLStoreWithConfig(path, config)
	if err != nil {
		t.Fatalf("NewJSONLStoreWithConfig: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func archivePathsForTest(t *testing.T, store *JSONLStore) []string {
	t.Helper()
	archives, err := store.archivePaths()
	if err != nil {
		t.Fatalf("archivePaths: %v", err)
	}
	return archives
}

func archiveNamesForTest(t *testing.T, store *JSONLStore) []string {
	t.Helper()
	archives := archivePathsForTest(t, store)
	names := make([]string, 0, len(archives))
	for _, path := range archives {
		names = append(names, filepath.Base(path))
	}
	return names
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

func TestJSONLStoreRotationDisabledByDefault(t *testing.T) {
	t.Parallel()
	store := newJSONLStore(t)

	mustAppend(t, store, audit.Entry{ID: "e1", Method: strings.Repeat("x", 128)})

	archives := archivePathsForTest(t, store)
	if len(archives) != 0 {
		t.Fatalf("archives = %v, want none", archives)
	}
}

func TestJSONLStoreRotatesWhenMaxSizeExceeded(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2026, 6, 10, 21, 46, 5, 0, time.FixedZone("local", 2*60*60))
	store, path := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		now:          func() time.Time { return fixed },
	})

	mustAppend(t, store, audit.Entry{ID: "rotated", Method: "ping"})

	archives := archivePathsForTest(t, store)
	if len(archives) != 1 {
		t.Fatalf("archives = %v, want 1 archive", archives)
	}
	if got, want := filepath.Base(archives[0]), "audit.jsonl.20260610T194605Z"; got != want {
		t.Fatalf("archive name = %q, want %q", got, want)
	}
	if active := readFile(t, path); len(active) != 0 {
		t.Fatalf("active file = %q, want empty after rotation", string(active))
	}
	if raw := readFile(t, archives[0]); !bytes.Contains(raw, []byte(`"id":"rotated"`)) {
		t.Fatalf("archive does not contain rotated entry: %s", string(raw))
	}
}

func TestJSONLStoreDoesNotSplitBatchDuringRotation(t *testing.T) {
	t.Parallel()
	store, path := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		now:          func() time.Time { return time.Date(2026, 6, 10, 21, 46, 5, 0, time.UTC) },
	})

	if err := store.AppendBatch([]audit.Entry{{ID: "batch-1"}, {ID: "batch-2"}}); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	archives := archivePathsForTest(t, store)
	if len(archives) != 1 {
		t.Fatalf("archives = %v, want 1 archive", archives)
	}
	raw := readFile(t, archives[0])
	if !bytes.Contains(raw, []byte(`"id":"batch-1"`)) || !bytes.Contains(raw, []byte(`"id":"batch-2"`)) {
		t.Fatalf("archive does not contain entire batch: %s", string(raw))
	}
	if active := readFile(t, path); len(active) != 0 {
		t.Fatalf("active file = %q, want empty after rotation", string(active))
	}
}

func TestJSONLStoreRotatedEntryContentRemainsUnchanged(t *testing.T) {
	t.Parallel()
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		now:          func() time.Time { return time.Date(2026, 6, 10, 21, 46, 5, 0, time.UTC) },
	})

	mustAppend(t, store, audit.Entry{ID: "signed", Method: "tools/call", Signature: "hmac-signature"})
	archives := archivePathsForTest(t, store)
	if len(archives) != 1 {
		t.Fatalf("archives = %v, want 1 archive", archives)
	}
	before := readFile(t, archives[0])

	if _, err := store.Query(audit.QueryFilter{}); err != nil {
		t.Fatalf("Query: %v", err)
	}
	after := readFile(t, archives[0])

	if !bytes.Equal(before, after) {
		t.Fatalf("archive changed after query\nbefore: %s\nafter: %s", string(before), string(after))
	}
	if !bytes.Contains(after, []byte(`"signature":"hmac-signature"`)) {
		t.Fatalf("archive lost signature: %s", string(after))
	}
}

func TestJSONLStoreArchiveNamesAreUniqueWithinSameSecond(t *testing.T) {
	t.Parallel()
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		now:          func() time.Time { return time.Date(2026, 6, 10, 21, 46, 5, 0, time.UTC) },
	})

	for i := 0; i < 3; i++ {
		mustAppend(t, store, audit.Entry{ID: fmt.Sprintf("same-second-%d", i)})
	}

	archives := archivePathsForTest(t, store)
	if len(archives) != 3 {
		t.Fatalf("archives = %v, want 3 archives", archives)
	}
	want := []string{
		"audit.jsonl.20260610T214605Z",
		"audit.jsonl.20260610T214605Z.1",
		"audit.jsonl.20260610T214605Z.2",
	}
	for i, path := range archives {
		if got := filepath.Base(path); got != want[i] {
			t.Fatalf("archive[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestJSONLStoreRetentionKeepsNewestArchives(t *testing.T) {
	t.Parallel()
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		MaxFiles:     2,
		now:          func() time.Time { return time.Date(2026, 6, 10, 21, 46, 5, 0, time.UTC) },
	})

	for i := 0; i < 3; i++ {
		mustAppend(t, store, audit.Entry{ID: fmt.Sprintf("retained-%d", i)})
	}

	archives := archivePathsForTest(t, store)
	if len(archives) != 2 {
		t.Fatalf("archives = %v, want 2 archives", archives)
	}
	want := []string{"audit.jsonl.20260610T214605Z.1", "audit.jsonl.20260610T214605Z.2"}
	for i, path := range archives {
		if got := filepath.Base(path); got != want[i] {
			t.Fatalf("archive[%d] = %q, want %q", i, got, want[i])
		}
	}
	raw := append(readFile(t, archives[0]), readFile(t, archives[1])...)
	if bytes.Contains(raw, []byte(`"id":"retained-0"`)) {
		t.Fatalf("oldest archive was retained unexpectedly: %s", string(raw))
	}
}

func TestJSONLStoreHourlyRotationFiresAtCutoff(t *testing.T) {
	now := time.Date(2026, 6, 10, 21, 30, 0, 0, time.UTC)
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		Interval: "hourly",
		now:      func() time.Time { return now },
	})

	mustAppend(t, store, audit.Entry{ID: "before-cutoff"})
	if archives := archivePathsForTest(t, store); len(archives) != 0 {
		t.Fatalf("archives before cutoff = %v, want none", archives)
	}

	now = time.Date(2026, 6, 10, 21, 59, 59, 999999999, time.UTC)
	mustAppend(t, store, audit.Entry{ID: "still-before-cutoff"})
	if archives := archivePathsForTest(t, store); len(archives) != 0 {
		t.Fatalf("archives just before cutoff = %v, want none", archives)
	}

	now = time.Date(2026, 6, 10, 22, 0, 0, 0, time.UTC)
	mustAppend(t, store, audit.Entry{ID: "at-cutoff"})
	names := archiveNamesForTest(t, store)
	want := []string{"audit.jsonl.20260610T220000Z"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names = %v, want %v", names, want)
	}
}

func TestJSONLStoreDailyRotationFiresAtCutoff(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		Interval: "daily",
		now:      func() time.Time { return now },
	})

	mustAppend(t, store, audit.Entry{ID: "before-midnight"})
	now = time.Date(2026, 6, 10, 23, 59, 59, 999999999, time.UTC)
	mustAppend(t, store, audit.Entry{ID: "still-before-midnight"})
	if archives := archivePathsForTest(t, store); len(archives) != 0 {
		t.Fatalf("archives before midnight = %v, want none", archives)
	}

	now = time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC)
	mustAppend(t, store, audit.Entry{ID: "midnight"})
	names := archiveNamesForTest(t, store)
	want := []string{"audit.jsonl.20260611T000000Z"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names = %v, want %v", names, want)
	}
}

func TestJSONLStoreSkipsTimeRotationWhenActiveWasEmpty(t *testing.T) {
	now := time.Date(2026, 6, 10, 21, 30, 0, 0, time.UTC)
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		Interval: "hourly",
		now:      func() time.Time { return now },
	})

	now = now.Add(3 * time.Hour)
	mustAppend(t, store, audit.Entry{ID: "first-entry-after-cutoff"})

	if archives := archivePathsForTest(t, store); len(archives) != 0 {
		t.Fatalf("archives after first append to empty file = %v, want none", archives)
	}
	entries, err := store.Query(audit.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "first-entry-after-cutoff" {
		t.Fatalf("entries = %+v, want first entry active", entries)
	}
}

func TestJSONLStoreStartupDoesNotCatchUpMissedCutoffs(t *testing.T) {
	now := time.Date(2026, 6, 10, 21, 30, 0, 0, time.UTC)
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		Interval: "hourly",
		now:      func() time.Time { return now },
	})

	if archives := archivePathsForTest(t, store); len(archives) != 0 {
		t.Fatalf("archives at startup = %v, want none", archives)
	}

	now = now.Add(3 * time.Hour)
	if archives := archivePathsForTest(t, store); len(archives) != 0 {
		t.Fatalf("archives after idle time without append = %v, want none", archives)
	}
}

func TestJSONLStoreIdleLongThenAppendCreatesOneArchive(t *testing.T) {
	now := time.Date(2026, 6, 10, 21, 30, 0, 0, time.UTC)
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		Interval: "hourly",
		now:      func() time.Time { return now },
	})

	mustAppend(t, store, audit.Entry{ID: "before-idle"})
	now = now.Add(72 * time.Hour)
	if archives := archivePathsForTest(t, store); len(archives) != 0 {
		t.Fatalf("archives while idle = %v, want none", archives)
	}

	mustAppend(t, store, audit.Entry{ID: "after-idle"})
	names := archiveNamesForTest(t, store)
	want := []string{"audit.jsonl.20260613T213000Z"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names = %v, want one archive %v", names, want)
	}
}

func TestJSONLStoreSizeAndTimeRotationOrder(t *testing.T) {
	now := time.Date(2026, 6, 10, 14, 30, 0, 0, time.UTC)
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 2048,
		Interval:     "hourly",
		now:          func() time.Time { return now },
	})

	mustAppend(t, store, audit.Entry{ID: "size-first", Method: strings.Repeat("x", 4096)})
	names := archiveNamesForTest(t, store)
	want := []string{"audit.jsonl.20260610T143000Z"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names after size rotation = %v, want %v", names, want)
	}

	now = time.Date(2026, 6, 10, 14, 45, 0, 0, time.UTC)
	mustAppend(t, store, audit.Entry{ID: "between-size-and-time"})
	names = archiveNamesForTest(t, store)
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names before time cutoff = %v, want %v", names, want)
	}

	now = time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)
	mustAppend(t, store, audit.Entry{ID: "time-second"})
	names = archiveNamesForTest(t, store)
	want = []string{"audit.jsonl.20260610T143000Z", "audit.jsonl.20260610T150000Z"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names after time rotation = %v, want %v", names, want)
	}
}

func TestJSONLStoreTimeRotationBeforeSize(t *testing.T) {
	now := time.Date(2026, 6, 10, 14, 30, 0, 0, time.UTC)
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1 << 20,
		Interval:     "hourly",
		now:          func() time.Time { return now },
	})

	mustAppend(t, store, audit.Entry{ID: "before-time"})
	now = time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)
	mustAppend(t, store, audit.Entry{ID: "time-first"})
	names := archiveNamesForTest(t, store)
	want := []string{"audit.jsonl.20260610T150000Z"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names = %v, want %v", names, want)
	}
}

func TestJSONLStoreSizeAndTimeEligibleCreateSingleArchive(t *testing.T) {
	now := time.Date(2026, 6, 10, 14, 30, 0, 0, time.UTC)
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 2048,
		Interval:     "hourly",
		now:          func() time.Time { return now },
	})

	mustAppend(t, store, audit.Entry{ID: "before-both"})
	now = time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)
	mustAppend(t, store, audit.Entry{ID: "both-eligible", Method: strings.Repeat("x", 4096)})
	names := archiveNamesForTest(t, store)
	want := []string{"audit.jsonl.20260610T150000Z"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names = %v, want %v", names, want)
	}
}

func TestJSONLStoreMaxAgeDaysUsesArchiveTimestamp(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	store, path := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		MaxAgeDays:   5,
		now:          func() time.Time { return now },
	})
	dir := filepath.Dir(path)
	for _, name := range []string{
		"audit.jsonl.20260604T115959Z",
		"audit.jsonl.20260605T120000Z",
		"audit.jsonl.not-an-archive",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"id":"manual"}`+"\n"), 0o600); err != nil {
			t.Fatalf("write archive %s: %v", name, err)
		}
	}

	mustAppend(t, store, audit.Entry{ID: "trigger-retention"})
	names := archiveNamesForTest(t, store)
	want := []string{
		"audit.jsonl.20260605T120000Z",
		"audit.jsonl.20260610T120000Z",
	}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names after age retention = %v, want %v", names, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl.not-an-archive")); err != nil {
		t.Fatalf("invalid archive name should be ignored by retention: %v", err)
	}
}

func TestJSONLStoreMaxAgeThenMaxFilesRetention(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	store, path := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		MaxAgeDays:   5,
		MaxFiles:     3,
		now:          func() time.Time { return now },
	})
	dir := filepath.Dir(path)
	for day := 1; day <= 10; day++ {
		ts := time.Date(2026, 6, day, 12, 0, 0, 0, time.UTC)
		name := "audit.jsonl." + ts.Format(archiveTimestampLayout)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"id":"manual"}`+"\n"), 0o600); err != nil {
			t.Fatalf("write archive %s: %v", name, err)
		}
	}

	mustAppend(t, store, audit.Entry{ID: "trigger-composed-retention"})
	names := archiveNamesForTest(t, store)
	want := []string{
		"audit.jsonl.20260609T120000Z",
		"audit.jsonl.20260610T120000Z",
		"audit.jsonl.20260610T120000Z.1",
	}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("archive names after composed retention = %v, want %v", names, want)
	}
}

func TestJSONLStoreQueryReadsArchivesAndActiveInOrder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ts := time.Date(2026, 6, 10, 21, 46, 5, 0, time.UTC)
	for _, item := range []struct {
		name string
		id   string
	}{
		{name: "audit.jsonl.20260610T214605Z", id: "old"},
		{name: "audit.jsonl.20260610T214606Z", id: "middle"},
		{name: "audit.jsonl.not-an-archive", id: "ignored"},
	} {
		raw := fmt.Sprintf(`{"id":%q,"timestamp":%q}`+"\n", item.id, ts.Format(time.RFC3339Nano))
		if err := os.WriteFile(filepath.Join(dir, item.name), []byte(raw), 0o600); err != nil {
			t.Fatalf("write archive %s: %v", item.name, err)
		}
	}
	store, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore: %v", err)
	}
	defer store.Close()
	mustAppend(t, store, audit.Entry{ID: "active", Timestamp: ts})

	entries, err := store.Query(audit.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		got = append(got, entry.ID)
	}
	want := []string{"old", "middle", "active"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
}

func TestJSONLStoreQuerySkipsInvalidJSONLinesInArchives(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	archivePath := filepath.Join(dir, "audit.jsonl.20260610T214605Z")
	if err := os.WriteFile(archivePath, []byte("{INVALID JSON}\n{\"id\":\"valid-archive\"}\n"), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	store, err := NewJSONLStore(path)
	if err != nil {
		t.Fatalf("NewJSONLStore: %v", err)
	}
	defer store.Close()
	mustAppend(t, store, audit.Entry{ID: "valid-active"})

	entries, err := store.Query(audit.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want 2 valid entries", entries)
	}
}

func TestJSONLStoreRotationErrorDoesNotFailAppend(t *testing.T) {
	t.Parallel()
	renameErr := errors.New("rename denied")
	renameFails := true
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		now:          func() time.Time { return time.Date(2026, 6, 10, 21, 46, 5, 0, time.UTC) },
		rename: func(oldPath, newPath string) error {
			if renameFails {
				return renameErr
			}
			return os.Rename(oldPath, newPath)
		},
	})

	if err := store.Append(audit.Entry{ID: "survives-failed-rotation"}); err != nil {
		t.Fatalf("Append after failed rotation: %v", err)
	}
	entries, err := store.Query(audit.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query after failed rotation: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "survives-failed-rotation" {
		t.Fatalf("entries after failed rotation = %+v", entries)
	}
	if archives := archivePathsForTest(t, store); len(archives) != 0 {
		t.Fatalf("archives after failed rotation = %v, want none", archives)
	}

	renameFails = false
	if err := store.Append(audit.Entry{ID: "retry-rotation"}); err != nil {
		t.Fatalf("Append after enabling rename: %v", err)
	}
	archives := archivePathsForTest(t, store)
	if len(archives) != 1 {
		t.Fatalf("archives after retry = %v, want 1", archives)
	}
	entries, err = store.Query(audit.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query after retry rotation: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries after retry rotation = %+v, want 2 entries", entries)
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

func TestJSONLStoreCloseIsIdempotentAfterRotation(t *testing.T) {
	t.Parallel()
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		now:          func() time.Time { return time.Date(2026, 6, 10, 21, 46, 5, 0, time.UTC) },
	})

	mustAppend(t, store, audit.Entry{ID: "rotated-before-close"})

	if err := store.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
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

func TestJSONLStoreConcurrentAppendsDuringRotationKeepAllEntries(t *testing.T) {
	t.Parallel()
	store, _ := newRotatingJSONLStore(t, JSONLConfig{
		MaxSizeBytes: 1,
		now:          func() time.Time { return time.Date(2026, 6, 10, 21, 46, 5, 0, time.UTC) },
	})
	const N = 100

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			if err := store.AppendBatch([]audit.Entry{{ID: fmt.Sprintf("rotating-entry-%d", i), Method: "ping"}}); err != nil {
				t.Errorf("AppendBatch %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	entries, err := store.Query(audit.QueryFilter{Limit: N + 10})
	if err != nil {
		t.Fatalf("Query after concurrent rotating appends: %v", err)
	}
	if len(entries) != N {
		t.Fatalf("entries = %d, want %d", len(entries), N)
	}
	seen := make(map[string]int, N)
	for _, entry := range entries {
		seen[entry.ID]++
	}
	for i := 0; i < N; i++ {
		id := fmt.Sprintf("rotating-entry-%d", i)
		if seen[id] != 1 {
			t.Fatalf("%s count = %d, want 1", id, seen[id])
		}
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
