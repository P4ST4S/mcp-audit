package proxy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/middleware"
	"github.com/P4ST4S/mcp-audit/internal/policy"
)

func TestRPCStatePurgeExpired(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	state := newRPCState()

	state.rememberClient("client-expired", pendingCall{startedAt: now.Add(-31 * time.Second)})
	state.rememberClient("client-fresh", pendingCall{startedAt: now.Add(-29 * time.Second)})
	state.rememberServer("server-expired", pendingCall{startedAt: now.Add(-time.Minute)})
	state.rememberServer("server-fresh", pendingCall{startedAt: now})

	if got := state.purgeExpired(now, 30*time.Second); got != 2 {
		t.Fatalf("purged %d pending calls, want 2", got)
	}
	if _, ok := state.takeClient("client-expired"); ok {
		t.Fatal("expired client call was not purged")
	}
	if _, ok := state.takeServer("server-expired"); ok {
		t.Fatal("expired server call was not purged")
	}
	if _, ok := state.takeClient("client-fresh"); !ok {
		t.Fatal("fresh client call was purged")
	}
	if _, ok := state.takeServer("server-fresh"); !ok {
		t.Fatal("fresh server call was purged")
	}
}

func TestStdioPolicyDeniesToolCallBeforeUpstream(t *testing.T) {
	store := &memoryAuditStore{}
	auditLogger := audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "stdio"})
	engine, err := policy.NewEngine(policy.Config{
		Enabled:       true,
		DefaultAction: policy.ActionAllow,
		Rules: []policy.Rule{
			{Action: policy.ActionDeny, ClientID: "claude-desktop", ServerID: "filesystem", ToolName: "delete_file", Reason: "destructive tool blocked"},
		},
	})
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	proxy := NewStdioProxy(StdioConfig{
		Audit:    auditLogger,
		Limiter:  middleware.NewRateLimiter(false, 0),
		Policy:   engine,
		ClientID: "claude-desktop",
		ServerID: "filesystem",
	})

	action := proxy.observeClientMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file"}}`))
	if len(action.reject) == 0 {
		t.Fatal("policy denied call was not rejected")
	}

	var response struct {
		Error audit.RPCError `json:"error"`
	}
	if err := json.Unmarshal(action.reject, &response); err != nil {
		t.Fatalf("decode reject response: %v", err)
	}
	if response.Error.Code != policyDeniedCode {
		t.Fatalf("error code = %d, want %d", response.Error.Code, policyDeniedCode)
	}
	if response.Error.Message != "policy denied" {
		t.Fatalf("error message = %q", response.Error.Message)
	}
	if len(store.entries) != 1 {
		t.Fatalf("stored entries = %d, want 1", len(store.entries))
	}
	entry := store.entries[0]
	if entry.ToolName != "delete_file" {
		t.Fatalf("tool name = %q, want delete_file", entry.ToolName)
	}
	if entry.Error == nil || entry.Error.Code != policyDeniedCode {
		t.Fatalf("entry error = %#v, want policy denial", entry.Error)
	}
}

type memoryAuditStore struct {
	entries []audit.Entry
}

func (s *memoryAuditStore) Append(entry audit.Entry) error {
	s.entries = append(s.entries, entry)
	return nil
}

func (s *memoryAuditStore) Query(audit.QueryFilter) ([]audit.Entry, error) {
	return append([]audit.Entry(nil), s.entries...), nil
}

func (s *memoryAuditStore) Stats() (audit.Stats, error) {
	return audit.Stats{}, nil
}

func (s *memoryAuditStore) Close() error {
	return nil
}
