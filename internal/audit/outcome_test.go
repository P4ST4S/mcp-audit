package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuildStatsCountsTerminalResponsesAndFailures(t *testing.T) {
	entries := []Entry{
		{Direction: DirectionServerToClient, Outcome: OutcomeSuccess, ToolName: "read"},
		{Direction: DirectionClientToServer, Outcome: OutcomeTimeout, ToolName: "read"},
		{Direction: DirectionServerToClient, Outcome: OutcomeSuccess, ToolName: "read", Result: json.RawMessage(`{"isError":true}`)},
		{Direction: DirectionServerToClient, Outcome: OutcomeUpstreamError, ToolName: "read"},
		{Direction: DirectionServerToClient, ToolName: "ignored legacy response"},
	}
	stats := BuildStats(entries)
	if stats.ErrorRate != 0.75 || len(stats.TopTools) != 1 || stats.TopTools[0].Count != 4 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestStatsAccumulatorDayBounds(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.FixedZone("local", 7200))
	stats := NewStatsAccumulator(now)
	start := time.Date(2026, 10, 17, 0, 0, 0, 0, now.Location())
	for _, timestamp := range []time.Time{start.Add(-1), start, start.AddDate(0, 0, 1).Add(-1), start.AddDate(0, 0, 1)} {
		stats.Add(Entry{Timestamp: timestamp, Outcome: OutcomeSuccess, Direction: DirectionServerToClient})
	}
	if got := stats.Stats(); got.TotalToday != 2 || got.ErrorRate != 0 {
		t.Fatalf("stats=%+v", got)
	}
}
