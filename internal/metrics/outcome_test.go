package metrics

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

func TestAuditEntryTerminalStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		entry  audit.Entry
		status string
	}{
		{"legacy success", audit.Entry{}, "ok"},
		{"success", audit.Entry{Outcome: audit.OutcomeSuccess}, "ok"},
		{"rpc", audit.Entry{Outcome: audit.OutcomeDenied, Error: &audit.RPCError{Code: -32030}}, "rpc_error"},
		{"tool", audit.Entry{Outcome: audit.OutcomeSuccess, Result: json.RawMessage(`{"isError":true}`)}, "tool_error"},
		{"invalid result", audit.Entry{Result: json.RawMessage(`bad`)}, "ok"},
		{"timeout", audit.Entry{Outcome: audit.OutcomeTimeout}, "timeout"},
		{"upstream", audit.Entry{Outcome: audit.OutcomeUpstreamError}, "upstream_error"},
		{"disconnect", audit.Entry{Outcome: audit.OutcomeClientDisconnect}, "client_disconnect"},
		{"malformed", audit.Entry{Outcome: audit.OutcomeMalformedUpstreamResponse}, "malformed_upstream_response"},
		{"cancelled", audit.Entry{Outcome: audit.OutcomeCancelled}, "cancelled"},
		{"internal", audit.Entry{Outcome: audit.OutcomeInternalError}, "internal_error"},
		{"denied", audit.Entry{Outcome: audit.OutcomeDenied}, "denied"},
		{"limited", audit.Entry{Outcome: audit.OutcomeRateLimited}, "rate_limited"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewPrometheusRecorder(Config{ToolLabels: true})
			if err != nil {
				t.Fatal(err)
			}
			tc.entry.Method, tc.entry.ToolName = "tools/call", "read"
			r.RecordAuditEntry(tc.entry)
			response := httptest.NewRecorder()
			r.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
			for _, name := range []string{"mcp_audit_entries_total{", "mcp_audit_tool_calls_total{"} {
				found := false
				for _, line := range strings.Split(response.Body.String(), "\n") {
					if strings.HasPrefix(line, name) && strings.Contains(line, `status="`+tc.status+`"`) {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing %s status=%s: %s", name, tc.status, response.Body.String())
				}
			}
		})
	}
}
