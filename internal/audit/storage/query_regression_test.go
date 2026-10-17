package storage

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

func TestSQLiteQueryFiltersBeforeLimit(t *testing.T) {
	store := newSQLiteStore(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := make([]audit.Entry, 10003)
	for i := range entries {
		entries[i] = audit.Entry{ID: fmt.Sprint(i), Timestamp: base.Add(time.Duration(i) * time.Second), Method: "ping", ClientID: "other"}
	}
	entries[0].Method, entries[0].ToolName, entries[0].ClientID = "tools/call", "read", "target"
	entries[1].Method, entries[1].ToolName, entries[1].ClientID = "tools/call", "read", "target"
	entries[1].Timestamp = base
	if err := store.AppendBatch(entries); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		filter audit.QueryFilter
		want   []string
	}{
		{"method", audit.QueryFilter{Method: "tools/call", Limit: 1}, []string{"0"}},
		{"tool", audit.QueryFilter{ToolName: "read"}, []string{"0", "1"}},
		{"client", audit.QueryFilter{ClientID: "target"}, []string{"0", "1"}},
		{"time", audit.QueryFilter{From: base, To: base}, []string{"0", "1"}},
		{"combined", audit.QueryFilter{Method: "tools/call", ToolName: "read", ClientID: "target", From: base, To: base}, []string{"0", "1"}},
		{"literal SQL", audit.QueryFilter{ClientID: "target' OR 1=1 --"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.Query(tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, e := range got {
				ids = append(ids, e.ID)
			}
			if !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("IDs = %v, want %v", ids, tc.want)
			}
		})
	}
}

func TestSQLiteQueryPreservesNanosecondBounds(t *testing.T) {
	store := newSQLiteStore(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, n := range []int{0, 1, 10, 100, 1000, 100000000, 110000000} {
		mustSQLiteAppend(t, store, audit.Entry{ID: fmt.Sprint(n), Timestamp: base.Add(time.Duration(n))})
	}
	for _, tc := range []struct {
		filter audit.QueryFilter
		want   []string
	}{
		{audit.QueryFilter{Limit: 1}, []string{"110000000"}},
		{audit.QueryFilter{From: base, To: base}, []string{"0"}},
		{audit.QueryFilter{From: base.Add(1), To: base.Add(100)}, []string{"100", "10", "1"}},
		{audit.QueryFilter{From: base.Add(1).In(time.FixedZone("offset", 3600)), To: base.Add(1)}, []string{"1"}},
		{audit.QueryFilter{From: base.Add(100000000), To: base.Add(110000000)}, []string{"110000000", "100000000"}},
	} {
		got, err := store.Query(tc.filter)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, e := range got {
			ids = append(ids, e.ID)
		}
		if !reflect.DeepEqual(ids, tc.want) {
			t.Fatalf("filter %+v: IDs = %v, want %v", tc.filter, ids, tc.want)
		}
	}
}

func TestStorageStatsIncludeCompleteHistory(t *testing.T) {
	for _, backend := range []string{"sqlite", "jsonl"} {
		t.Run(backend, func(t *testing.T) {
			var store audit.Store
			var err error
			if backend == "sqlite" {
				store, err = NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
			} else {
				store, err = NewJSONLStoreWithConfig(filepath.Join(t.TempDir(), "audit.jsonl"), JSONLConfig{MaxSizeBytes: 1, MaxFiles: 5})
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Error(err)
				}
			})
			base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			batch := make([]audit.Entry, 10001)
			for i := range batch {
				batch[i] = audit.Entry{ID: fmt.Sprint(i), Timestamp: base.Add(time.Duration(i) * time.Second), Direction: audit.DirectionClientToServer, ToolName: "read"}
			}
			batch[0].Error = &audit.RPCError{Code: -1}
			if err := store.(interface{ AppendBatch([]audit.Entry) error }).AppendBatch(batch); err != nil {
				t.Fatal(err)
			}
			stats, err := store.Stats()
			if err != nil {
				t.Fatal(err)
			}
			if len(stats.TopTools) != 1 || stats.TopTools[0].Count != len(batch) || stats.ErrorRate != 1/float64(len(batch)) {
				t.Fatalf("stats = %+v, want all %d entries including the oldest failure", stats, len(batch))
			}
		})
	}
}

func BenchmarkSQLiteFilteredHistory(b *testing.B) {
	store, err := NewSQLiteStore(filepath.Join(b.TempDir(), "audit.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	entries := make([]audit.Entry, 20000)
	for i := range entries {
		entries[i] = audit.Entry{ID: fmt.Sprint(i), ClientID: "other", Timestamp: time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)}
	}
	entries[0].ClientID = "target"
	if err := store.AppendBatch(entries); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.Query(audit.QueryFilter{ClientID: "target", Limit: 1}); err != nil {
			b.Fatal(err)
		}
	}
}
