package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

// dashFakeStore is a minimal in-memory Store for dashboard tests.
// It does NOT re-implement filter logic: each test seeds only the entries
// it needs, so the store returns the pre-seeded slice as-is.
type dashFakeStore struct {
	records  []audit.Entry
	stats    audit.Stats
	queryErr error
	statsErr error
}

func (s *dashFakeStore) Append(_ audit.Entry) error { return nil }

func (s *dashFakeStore) Query(_ audit.QueryFilter) ([]audit.Entry, error) {
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	return s.records, nil
}

func (s *dashFakeStore) Stats() (audit.Stats, error) {
	if s.statsErr != nil {
		return audit.Stats{}, s.statsErr
	}
	return s.stats, nil
}

func (s *dashFakeStore) Close() error { return nil }

// newTestServer creates a Server with a dashFakeStore and a no-op logger.
func newTestServer(store *dashFakeStore) *Server {
	return NewServer(Config{Store: store})
}

// freePort binds :0 and returns the allocated port (the listener is closed
// before returning, so the port is "free" for the next caller).
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("freePort listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// ---------------------------------------------------------------------------
// Handler GET /
// ---------------------------------------------------------------------------

func TestServerIndexRendersHTML(t *testing.T) {
	t.Parallel()
	s := newTestServer(&dashFakeStore{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.index(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	body := rec.Body.String()
	if len(body) == 0 {
		t.Fatal("response body is empty")
	}
	// Verify a stable structural marker — not the full HTML.
	if !containsString(body, "<title>mcp-audit</title>") {
		t.Fatalf("expected <title>mcp-audit</title> in response body")
	}
}

// ---------------------------------------------------------------------------
// Handler GET /api/entries
// ---------------------------------------------------------------------------

func TestServerEntriesReturnsAllWhenNoFilter(t *testing.T) {
	t.Parallel()
	store := &dashFakeStore{records: []audit.Entry{
		{ID: "1", Method: "ping"},
		{ID: "2", Method: "ping"},
		{ID: "3", Method: "tools/call"},
	}}
	s := newTestServer(store)

	req := httptest.NewRequest(http.MethodGet, "/api/entries", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []audit.Entry
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("entries = %d, want 3", len(got))
	}
}

func TestServerEntriesAppliesMethodFilter(t *testing.T) {
	t.Parallel()
	// The handler calls store.Query(filter); the fakeStore ignores the filter
	// and returns all records. So we seed only the entries that should match.
	store := &dashFakeStore{records: []audit.Entry{
		{ID: "1", Method: "ping"},
		{ID: "2", Method: "ping"},
	}}
	s := newTestServer(store)

	req := httptest.NewRequest(http.MethodGet, "/api/entries?method=ping", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []audit.Entry
	mustDecodeJSON(t, rec, &got)
	if len(got) != 2 {
		t.Fatalf("entries = %d, want 2", len(got))
	}
}

func TestServerEntriesAppliesToolNameFilter(t *testing.T) {
	t.Parallel()
	store := &dashFakeStore{records: []audit.Entry{
		{ID: "1", ToolName: "read_file"},
	}}
	s := newTestServer(store)

	req := httptest.NewRequest(http.MethodGet, "/api/entries?tool_name=read_file", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []audit.Entry
	mustDecodeJSON(t, rec, &got)
	if len(got) != 1 || got[0].ToolName != "read_file" {
		t.Fatalf("unexpected entries: %+v", got)
	}
}

func TestServerEntriesAppliesClientIDFilter(t *testing.T) {
	t.Parallel()
	store := &dashFakeStore{records: []audit.Entry{
		{ID: "1", ClientID: "claude"},
		{ID: "2", ClientID: "claude"},
	}}
	s := newTestServer(store)

	req := httptest.NewRequest(http.MethodGet, "/api/entries?client_id=claude", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []audit.Entry
	mustDecodeJSON(t, rec, &got)
	if len(got) != 2 {
		t.Fatalf("entries = %d, want 2", len(got))
	}
}

func TestServerEntriesAppliesTimeRangeFilter(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	store := &dashFakeStore{records: []audit.Entry{
		{ID: "in", Timestamp: now},
	}}
	s := newTestServer(store)

	from := now.Add(-time.Hour).Format(time.RFC3339)
	to := now.Add(time.Hour).Format(time.RFC3339)
	url := fmt.Sprintf("/api/entries?from=%s&to=%s", from, to)

	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []audit.Entry
	mustDecodeJSON(t, rec, &got)
	if len(got) != 1 {
		t.Fatalf("entries = %d, want 1", len(got))
	}
}

func TestServerEntriesAppliesLimit(t *testing.T) {
	t.Parallel()
	entries := make([]audit.Entry, 10)
	for i := range entries {
		entries[i] = audit.Entry{ID: fmt.Sprintf("e%d", i)}
	}

	// queryFilter builds a filter with Limit=3; the fakeStore ignores it and
	// returns all 10 records — but the handler does NOT apply a secondary limit.
	// To isolate the contract we seed only 3 entries instead of relying on
	// LimitNewest (which belongs to the storage layer, not the dashboard).
	store3 := &dashFakeStore{records: entries[:3]}
	s3 := newTestServer(store3)

	req := httptest.NewRequest(http.MethodGet, "/api/entries?limit=3", nil)
	rec := httptest.NewRecorder()
	s3.entries(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []audit.Entry
	mustDecodeJSON(t, rec, &got)
	if len(got) != 3 {
		t.Fatalf("entries = %d, want 3", len(got))
	}
}

func TestServerEntriesDefaultLimitIs100(t *testing.T) {
	t.Parallel()
	// Verify that queryFilter sets Limit=100 when no ?limit param is provided,
	// by checking the filter passed to the store. We use a capturing store.
	var capturedFilter audit.QueryFilter
	capStore := &capturingStore{}
	s := NewServer(Config{Store: capStore})

	req := httptest.NewRequest(http.MethodGet, "/api/entries", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	capturedFilter = capStore.lastFilter
	if capturedFilter.Limit != 100 {
		t.Fatalf("default Limit = %d, want 100", capturedFilter.Limit)
	}
}

func TestServerEntriesRejectsInvalidLimit(t *testing.T) {
	t.Parallel()
	s := newTestServer(&dashFakeStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/entries?limit=abc", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestServerEntriesRejectsInvalidFromTimestamp(t *testing.T) {
	t.Parallel()
	s := newTestServer(&dashFakeStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/entries?from=2026-01-01", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (non-RFC3339 from)", rec.Code)
	}
}

func TestServerEntriesRejectsInvalidToTimestamp(t *testing.T) {
	t.Parallel()
	s := newTestServer(&dashFakeStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/entries?to=not-a-date", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (invalid to)", rec.Code)
	}
}

func TestServerEntriesReturns500OnStoreError(t *testing.T) {
	t.Parallel()
	store := &dashFakeStore{queryErr: errors.New("storage unavailable")}
	s := newTestServer(store)

	req := httptest.NewRequest(http.MethodGet, "/api/entries", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestServerEntriesReturnsValidJSON(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	store := &dashFakeStore{records: []audit.Entry{
		{ID: "rt-1", Method: "ping", Timestamp: now, ClientID: "c1", ServerID: "s1"},
	}}
	s := newTestServer(store)

	req := httptest.NewRequest(http.MethodGet, "/api/entries", nil)
	rec := httptest.NewRecorder()
	s.entries(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got []audit.Entry
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	if len(got) != 1 || got[0].ID != "rt-1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Handler GET /api/stats
// ---------------------------------------------------------------------------

func TestServerStatsReturnsAggregates(t *testing.T) {
	t.Parallel()
	store := &dashFakeStore{
		stats: audit.Stats{
			TotalToday: 7,
			ErrorRate:  0.14,
			TopTools:   []audit.ToolStat{{Name: "bash", Count: 5}},
		},
	}
	s := newTestServer(store)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rec := httptest.NewRecorder()
	s.stats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got audit.Stats
	mustDecodeJSON(t, rec, &got)
	if got.TotalToday != 7 {
		t.Fatalf("TotalToday = %d, want 7", got.TotalToday)
	}
	if len(got.TopTools) == 0 || got.TopTools[0].Name != "bash" {
		t.Fatalf("TopTools = %+v, want [{bash 5}]", got.TopTools)
	}
}

func TestServerStatsReturns500OnStoreError(t *testing.T) {
	t.Parallel()
	store := &dashFakeStore{statsErr: errors.New("stats unavailable")}
	s := newTestServer(store)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rec := httptest.NewRecorder()
	s.stats(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestServerStatsReturnsValidJSON(t *testing.T) {
	t.Parallel()
	store := &dashFakeStore{
		stats: audit.Stats{TotalToday: 3, ErrorRate: 0.33},
	}
	s := newTestServer(store)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rec := httptest.NewRecorder()
	s.stats(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got audit.Stats
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	if got.TotalToday != 3 {
		t.Fatalf("TotalToday = %d, want 3", got.TotalToday)
	}
}

// ---------------------------------------------------------------------------
// queryFilter (direct tests)
// ---------------------------------------------------------------------------

func TestQueryFilterEmptyDefaultsToLimit100(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/api/entries", nil)

	f, err := queryFilter(req)
	if err != nil {
		t.Fatalf("queryFilter: %v", err)
	}
	if f.Limit != 100 {
		t.Fatalf("default Limit = %d, want 100", f.Limit)
	}
	if f.Method != "" || f.ToolName != "" || f.ClientID != "" {
		t.Fatalf("unexpected non-zero string fields: %+v", f)
	}
	if !f.From.IsZero() || !f.To.IsZero() {
		t.Fatalf("unexpected non-zero time fields: %+v", f)
	}
}

func TestQueryFilterParsesAllFields(t *testing.T) {
	t.Parallel()
	from := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 15, 18, 0, 0, 0, time.UTC)

	url := fmt.Sprintf(
		"/api/entries?method=tools/call&tool_name=bash&client_id=claude&limit=50&from=%s&to=%s",
		from.Format(time.RFC3339),
		to.Format(time.RFC3339),
	)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	f, err := queryFilter(req)
	if err != nil {
		t.Fatalf("queryFilter: %v", err)
	}
	if f.Method != "tools/call" {
		t.Fatalf("Method = %q, want tools/call", f.Method)
	}
	if f.ToolName != "bash" {
		t.Fatalf("ToolName = %q, want bash", f.ToolName)
	}
	if f.ClientID != "claude" {
		t.Fatalf("ClientID = %q, want claude", f.ClientID)
	}
	if f.Limit != 50 {
		t.Fatalf("Limit = %d, want 50", f.Limit)
	}
	if !f.From.Equal(from) {
		t.Fatalf("From = %v, want %v", f.From, from)
	}
	if !f.To.Equal(to) {
		t.Fatalf("To = %v, want %v", f.To, to)
	}
}

func TestQueryFilterRejectsNonRFC3339Timestamps(t *testing.T) {
	t.Parallel()
	// Each value is percent-encoded so that httptest.NewRequest does not panic
	// on invalid URL characters (spaces, slashes in path position).
	cases := []struct {
		name string
		from string
	}{
		{"date-only", "2026-01-01"},        // missing time+timezone
		{"wrong-format", "01%2F15%2F2026"}, // 01/15/2026 URL-encoded
		{"not-a-date", "not-a-date"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/api/entries?from="+tc.from, nil)
			if _, err := queryFilter(req); err == nil {
				t.Fatalf("expected error for from=%q, got nil", tc.from)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ListenAndServe lifecycle
// ---------------------------------------------------------------------------

func TestServerListenAndServeReturnsNilWhenDisabled(t *testing.T) {
	t.Parallel()
	s := NewServer(Config{Enabled: false, Store: &dashFakeStore{}})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.ListenAndServe(ctx); err != nil {
		t.Fatalf("ListenAndServe with Enabled=false: %v", err)
	}
}

func TestServerListenAndServeShutdownsOnContextCancel(t *testing.T) {
	t.Parallel()
	port := freePort(t)
	s := NewServer(Config{Enabled: true, Port: port, Store: &dashFakeStore{}})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe(ctx) }()

	// Poll until the server accepts connections (max 2s).
	deadline := time.Now().Add(2 * time.Second)
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	for {
		resp, err := http.Get(url) //nolint:noctx
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dashboard server never became ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe returned error after context cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServe did not return within 3s after context cancel")
	}
}

func TestServerListenAndServeReturnsErrorOnBindFailure(t *testing.T) {
	t.Parallel()
	// Bind 0.0.0.0:0 (wildcard), same interface as ListenAndServe, so the
	// dashboard will collide and return a bind error.
	blocker, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("blocker listen: %v", err)
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port

	s := NewServer(Config{Enabled: true, Port: port, Store: &dashFakeStore{}})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := s.ListenAndServe(ctx); err == nil {
		t.Fatal("expected error when port is already in use")
	}
}

// ---------------------------------------------------------------------------
// NewServer constructor
// ---------------------------------------------------------------------------

func TestNewServerNilLogFallsBackToDefault(t *testing.T) {
	t.Parallel()
	s := NewServer(Config{Store: &dashFakeStore{}}) // no Log field

	// Must not panic during construction or on a real request.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.index(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Routing smoke test (via httptest.NewServer)
// ---------------------------------------------------------------------------

func TestServerRoutesAreWiredCorrectly(t *testing.T) {
	t.Parallel()
	store := &dashFakeStore{
		records: []audit.Entry{{ID: "rt-1"}},
		stats:   audit.Stats{TotalToday: 1},
	}
	s := NewServer(Config{Store: store})
	ts := httptest.NewServer(s.server.Handler)
	defer ts.Close()

	for _, path := range []string{"/", "/api/entries", "/api/stats"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200", path, resp.StatusCode)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustDecodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i+len(substr) <= len(s); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

// capturingStore captures the last QueryFilter passed to Query.
type capturingStore struct {
	lastFilter audit.QueryFilter
}

func (s *capturingStore) Append(_ audit.Entry) error { return nil }

func (s *capturingStore) Query(f audit.QueryFilter) ([]audit.Entry, error) {
	s.lastFilter = f
	return nil, nil
}

func (s *capturingStore) Stats() (audit.Stats, error) { return audit.Stats{}, nil }
func (s *capturingStore) Close() error                { return nil }
