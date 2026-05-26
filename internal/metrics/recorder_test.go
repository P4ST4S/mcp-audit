package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

func TestPrometheusRecorderExposesApplicationMetrics(t *testing.T) {
	recorder, err := NewPrometheusRecorder(Config{Path: "/metrics", ToolLabels: true})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	recorder.RecordAuditEntry(audit.Entry{
		Direction: audit.DirectionClientToServer,
		Transport: "stdio",
		Method:    "tools/call",
		ToolName:  "read_file",
	})
	recorder.RecordRateLimitRejection("client", "read_file")
	recorder.RecordStorageWrite("jsonl", "async", "ok", 10*time.Millisecond, 3)
	recorder.SetAsyncQueueDepth(2)
	recorder.SetAsyncQueueCapacity(10)
	recorder.RecordAsyncBackpressure()
	recorder.RecordAsyncBatch(3)

	req := httptest.NewRequest("GET", "/metrics", nil)
	resp := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(resp, req)
	body := resp.Body.String()

	expected := []string{
		`mcp_audit_entries_total{direction="client_to_server",method="tools/call",status="ok",transport="stdio"} 1`,
		`mcp_audit_tool_calls_total{status="ok",tool_name="read_file",transport="stdio"} 1`,
		`mcp_audit_rate_limit_rejections_total{client_id="client",tool_name="read_file"} 1`,
		`mcp_audit_storage_writes_total{backend="jsonl",mode="async",status="ok"} 3`,
		`mcp_audit_async_queue_depth 2`,
		`mcp_audit_async_queue_capacity 10`,
		`mcp_audit_async_backpressure_total 1`,
		`mcp_audit_async_batches_total 1`,
	}
	for _, want := range expected {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q\n%s", want, body)
		}
	}
}

func TestPrometheusRecorderCanDisableToolLabels(t *testing.T) {
	recorder, err := NewPrometheusRecorder(Config{ToolLabels: false})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	recorder.RecordAuditEntry(audit.Entry{
		Direction: audit.DirectionClientToServer,
		Transport: "stdio",
		Method:    "tools/call",
		ToolName:  "read_file",
	})
	recorder.RecordRateLimitRejection("client", "read_file")

	req := httptest.NewRequest("GET", "/metrics", nil)
	resp := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(resp, req)
	body := resp.Body.String()

	if strings.Contains(body, "mcp_audit_tool_calls_total") {
		t.Fatalf("tool metrics should be disabled\n%s", body)
	}
	if strings.Contains(body, "mcp_audit_rate_limit_rejections_total") {
		t.Fatalf("rate limit tool labels should be disabled\n%s", body)
	}
}
