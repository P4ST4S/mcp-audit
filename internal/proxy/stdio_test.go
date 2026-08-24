package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
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
	if entry.Outcome != audit.OutcomeDenied {
		t.Fatalf("entry outcome = %q, want denied", entry.Outcome)
	}
	if entry.AuditOperationID == "" {
		t.Fatal("entry audit_operation_id is empty")
	}
}

func TestStdioPolicyDeniesResourceOperation(t *testing.T) {
	store := &memoryAuditStore{}
	engine, err := policy.NewEngine(policy.Config{
		Enabled: true,
		Scope:   policy.ScopeAllOperations,
		Rules:   []policy.Rule{{Action: policy.ActionDeny, Method: "resources/read", Name: "file:///secret"}},
	})
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	proxy := NewStdioProxy(StdioConfig{
		Audit:    audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "stdio"}),
		Limiter:  middleware.NewRateLimiter(false, 0),
		Policy:   engine,
		ClientID: "local-client",
		ServerID: "filesystem",
	})
	action := proxy.observeClientMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///secret"}}`))
	if len(action.reject) == 0 || len(store.entries) != 1 {
		t.Fatalf("reject/audit = %q/%#v", action.reject, store.entries)
	}
	if store.entries[0].Method != "resources/read" || store.entries[0].ToolName != "" || store.entries[0].Error == nil {
		t.Fatalf("entry = %#v", store.entries[0])
	}
}

func TestStdioMalformedUpstreamResponseFinalizesPendingCall(t *testing.T) {
	store := &memoryAuditStore{}
	proxy := NewStdioProxy(StdioConfig{
		Audit:   audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "stdio"}),
		Limiter: middleware.NewRateLimiter(false, 0),
	})

	proxy.observeClientMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`))
	proxy.observeServerMessage([]byte(`not-json`))

	if len(store.entries) != 1 {
		t.Fatalf("stored entries = %d, want 1", len(store.entries))
	}
	entry := store.entries[0]
	if entry.Outcome != audit.OutcomeMalformedUpstreamResponse {
		t.Fatalf("outcome = %q, want malformed_upstream_response", entry.Outcome)
	}
	if entry.Direction != audit.DirectionServerToClient {
		t.Fatalf("direction = %q, want server-to-client", entry.Direction)
	}
	if entry.AuditOperationID == "" {
		t.Fatal("audit_operation_id is empty")
	}

	proxy.observeServerMessage([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	if len(store.entries) != 1 {
		t.Fatalf("late response created a duplicate terminal entry: %d", len(store.entries))
	}
}

func TestStdioExpiredPendingCallFinalizesAsTimeout(t *testing.T) {
	store := &memoryAuditStore{}
	proxy := NewStdioProxy(StdioConfig{
		Audit:   audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "stdio"}),
		Limiter: middleware.NewRateLimiter(false, 0),
	})
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	proxy.observeClientMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/read"}`))
	call, ok := proxy.state.takeClient("1")
	if !ok {
		t.Fatal("pending call was not registered")
	}
	call.startedAt = now.Add(-pendingCallTTL - time.Second)
	proxy.state.rememberClient("1", call)

	proxy.finalizeCalls(proxy.state.takeExpired(now, pendingCallTTL), audit.OutcomeTimeout)
	if len(store.entries) != 1 {
		t.Fatalf("stored entries = %d, want 1", len(store.entries))
	}
	if store.entries[0].Outcome != audit.OutcomeTimeout {
		t.Fatalf("outcome = %q, want timeout", store.entries[0].Outcome)
	}
	if _, ok := proxy.state.takeClient("1"); ok {
		t.Fatal("expired call remains pending")
	}
}

func TestStdioUpstreamTerminationFinalizesBothDirections(t *testing.T) {
	store := &memoryAuditStore{}
	proxy := NewStdioProxy(StdioConfig{
		Audit:   audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "stdio"}),
		Limiter: middleware.NewRateLimiter(false, 0),
	})

	proxy.observeClientMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`))
	proxy.observeServerMessage([]byte(`{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage"}`))
	proxy.finalizeAll(audit.OutcomeUpstreamError)

	if len(store.entries) != 2 {
		t.Fatalf("stored entries = %d, want 2", len(store.entries))
	}
	directions := make(map[string]bool)
	for _, entry := range store.entries {
		if entry.Outcome != audit.OutcomeUpstreamError {
			t.Fatalf("outcome = %q, want upstream_error", entry.Outcome)
		}
		directions[entry.Direction] = true
	}
	if !directions[audit.DirectionServerToClient] || !directions[audit.DirectionClientToServer] {
		t.Fatalf("terminal directions = %#v, want both directions", directions)
	}
}

func TestStdioUpstreamWriteFailureFinalizesAcceptedCall(t *testing.T) {
	store := &memoryAuditStore{}
	proxy := NewStdioProxy(StdioConfig{
		Audit:   audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "stdio"}),
		Limiter: middleware.NewRateLimiter(false, 0),
	})

	proxy.pipeClientToServer(
		context.Background(),
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`+"\n"),
		errorWriter{},
		io.Discard,
		&sync.Mutex{},
	)

	if len(store.entries) != 1 || store.entries[0].Outcome != audit.OutcomeUpstreamError {
		t.Fatalf("entries = %#v, want one upstream_error", store.entries)
	}
}

func TestStdioClientWriteFailureFinalizesPendingCall(t *testing.T) {
	store := &memoryAuditStore{}
	proxy := NewStdioProxy(StdioConfig{
		Audit:   audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "stdio"}),
		Limiter: middleware.NewRateLimiter(false, 0),
	})
	proxy.observeClientMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`))

	proxy.pipeServerToClient(
		context.Background(),
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`+"\n"),
		errorWriter{},
		&sync.Mutex{},
	)

	if len(store.entries) != 1 || store.entries[0].Outcome != audit.OutcomeClientDisconnect {
		t.Fatalf("entries = %#v, want one client_disconnect", store.entries)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
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
