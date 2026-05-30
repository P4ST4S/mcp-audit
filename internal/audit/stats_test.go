package audit

import (
	"testing"
	"time"
)

func TestMatchFilterEmptyFilterMatchesAll(t *testing.T) {
	entry := Entry{Method: "tools/call", ToolName: "read_file", ClientID: "claude"}
	if !MatchFilter(entry, QueryFilter{}) {
		t.Fatal("empty filter should match all entries")
	}
}

func TestMatchFilterMethodMismatch(t *testing.T) {
	entry := Entry{Method: "tools/call"}
	if MatchFilter(entry, QueryFilter{Method: "resources/read"}) {
		t.Fatal("filter should not match different method")
	}
}

func TestMatchFilterToolNameMismatch(t *testing.T) {
	entry := Entry{ToolName: "read_file"}
	if MatchFilter(entry, QueryFilter{ToolName: "write_file"}) {
		t.Fatal("filter should not match different tool name")
	}
}

func TestMatchFilterClientIDMismatch(t *testing.T) {
	entry := Entry{ClientID: "claude"}
	if MatchFilter(entry, QueryFilter{ClientID: "cursor"}) {
		t.Fatal("filter should not match different client id")
	}
}

func TestMatchFilterTimestampBeforeFrom(t *testing.T) {
	entry := Entry{Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	filter := QueryFilter{From: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	if MatchFilter(entry, filter) {
		t.Fatal("entry before From should not match")
	}
}

func TestMatchFilterTimestampAfterTo(t *testing.T) {
	entry := Entry{Timestamp: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)}
	filter := QueryFilter{To: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	if MatchFilter(entry, filter) {
		t.Fatal("entry after To should not match")
	}
}

func TestMatchFilterWithinTimeWindow(t *testing.T) {
	entry := Entry{
		Method:    "tools/call",
		ToolName:  "read_file",
		ClientID:  "claude",
		Timestamp: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
	}
	filter := QueryFilter{
		Method:   "tools/call",
		ToolName: "read_file",
		ClientID: "claude",
		From:     time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		To:       time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
	}
	if !MatchFilter(entry, filter) {
		t.Fatal("entry within all filter constraints should match")
	}
}

func TestLimitNewestSortsAndLimits(t *testing.T) {
	entries := []Entry{
		{ID: "a", Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{ID: "b", Timestamp: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
		{ID: "c", Timestamp: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
	}
	got := LimitNewest(entries, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].ID != "b" || got[1].ID != "c" {
		t.Fatalf("expected order [b, c], got [%s, %s]", got[0].ID, got[1].ID)
	}
}

func TestLimitNewestDefaultLimitWhenZeroOrNegative(t *testing.T) {
	entries := make([]Entry, 150)
	for i := range entries {
		entries[i] = Entry{Timestamp: time.Now().Add(-time.Duration(i) * time.Second)}
	}
	if got := LimitNewest(entries, 0); len(got) != 100 {
		t.Fatalf("zero limit should default to 100, got %d", len(got))
	}
	if got := LimitNewest(entries, -5); len(got) != 100 {
		t.Fatalf("negative limit should default to 100, got %d", len(got))
	}
}

func TestLimitNewestKeepsAllWhenUnderLimit(t *testing.T) {
	entries := []Entry{
		{ID: "a", Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{ID: "b", Timestamp: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
	}
	got := LimitNewest(entries, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
}

func TestBuildStatsCountsOnlyClientToServer(t *testing.T) {
	now := time.Now()
	entries := []Entry{
		{Direction: DirectionClientToServer, ToolName: "read", Timestamp: now},
		{Direction: DirectionServerToClient, ToolName: "read", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "write", Timestamp: now},
	}
	stats := BuildStats(entries)
	if stats.TotalToday != 2 {
		t.Fatalf("expected 2 client-to-server entries today, got %d", stats.TotalToday)
	}
}

func TestBuildStatsErrorRate(t *testing.T) {
	now := time.Now()
	entries := []Entry{
		{Direction: DirectionClientToServer, Timestamp: now, Error: &RPCError{Code: -1}},
		{Direction: DirectionClientToServer, Timestamp: now, Error: &RPCError{Code: -2}},
		{Direction: DirectionClientToServer, Timestamp: now},
		{Direction: DirectionClientToServer, Timestamp: now},
	}
	stats := BuildStats(entries)
	if stats.ErrorRate != 0.5 {
		t.Fatalf("expected error rate 0.5, got %f", stats.ErrorRate)
	}
}

func TestBuildStatsZeroErrorRateWhenNoEntries(t *testing.T) {
	stats := BuildStats(nil)
	if stats.ErrorRate != 0 {
		t.Fatalf("expected zero error rate for empty input, got %f", stats.ErrorRate)
	}
	if stats.TotalToday != 0 {
		t.Fatalf("expected zero total for empty input, got %d", stats.TotalToday)
	}
}

func TestBuildStatsTopToolsSortedByCount(t *testing.T) {
	now := time.Now()
	entries := []Entry{
		{Direction: DirectionClientToServer, ToolName: "read", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "read", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "read", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "write", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "delete", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "delete", Timestamp: now},
	}
	stats := BuildStats(entries)
	if len(stats.TopTools) != 3 {
		t.Fatalf("expected 3 distinct tools, got %d", len(stats.TopTools))
	}
	if stats.TopTools[0].Name != "read" || stats.TopTools[0].Count != 3 {
		t.Fatalf("expected read=3 first, got %+v", stats.TopTools[0])
	}
	if stats.TopTools[1].Name != "delete" || stats.TopTools[1].Count != 2 {
		t.Fatalf("expected delete=2 second, got %+v", stats.TopTools[1])
	}
}

func TestBuildStatsTopToolsAlphabeticalTieBreak(t *testing.T) {
	now := time.Now()
	entries := []Entry{
		{Direction: DirectionClientToServer, ToolName: "zeta", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "alpha", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "beta", Timestamp: now},
	}
	stats := BuildStats(entries)
	if stats.TopTools[0].Name != "alpha" {
		t.Fatalf("ties should break alphabetically, got %s first", stats.TopTools[0].Name)
	}
}

func TestBuildStatsTopToolsLimitedToFive(t *testing.T) {
	now := time.Now()
	entries := []Entry{
		{Direction: DirectionClientToServer, ToolName: "t1", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "t2", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "t3", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "t4", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "t5", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "t6", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "t7", Timestamp: now},
	}
	stats := BuildStats(entries)
	if len(stats.TopTools) != 5 {
		t.Fatalf("top tools should be capped at 5, got %d", len(stats.TopTools))
	}
}

func TestBuildStatsIgnoresEntriesBeforeToday(t *testing.T) {
	yesterday := time.Now().Add(-48 * time.Hour)
	now := time.Now()
	entries := []Entry{
		{Direction: DirectionClientToServer, Timestamp: yesterday},
		{Direction: DirectionClientToServer, Timestamp: now},
	}
	stats := BuildStats(entries)
	if stats.TotalToday != 1 {
		t.Fatalf("expected only today's entry in TotalToday, got %d", stats.TotalToday)
	}
}

func TestBuildStatsIgnoresEntriesWithoutToolName(t *testing.T) {
	now := time.Now()
	entries := []Entry{
		{Direction: DirectionClientToServer, ToolName: "read", Timestamp: now},
		{Direction: DirectionClientToServer, ToolName: "", Timestamp: now},
	}
	stats := BuildStats(entries)
	if len(stats.TopTools) != 1 {
		t.Fatalf("entries without tool name should not appear in TopTools, got %d entries", len(stats.TopTools))
	}
}
