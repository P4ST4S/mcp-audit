package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
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
	recorder.RecordPolicyDecision("deny")
	recorder.RecordHTTPUpstreamRetry("503")
	recorder.RecordStorageWrite("jsonl", "async", "ok", 10*time.Millisecond, 3)
	recorder.RecordOTelExport("ok", 20*time.Millisecond, 2)
	recorder.RecordOTelDrop("queue_full", 1)
	recorder.SetOTelQueueDepth(1)
	recorder.SetOTelQueueCapacity(4)
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
		`mcp_audit_policy_decisions_total{action="deny"} 1`,
		`mcp_audit_tool_calls_total{status="ok",tool_name="read_file",transport="stdio"} 1`,
		`mcp_audit_rate_limit_rejections_total{client_id="client",tool_name="read_file"} 1`,
		`mcp_audit_http_upstream_retries_total{reason="503"} 1`,
		`mcp_audit_storage_writes_total{backend="jsonl",mode="async",status="ok"} 3`,
		`mcp_audit_otel_export_requests_total{status="ok"} 1`,
		`mcp_audit_otel_spans_total{status="ok"} 2`,
		`mcp_audit_otel_spans_dropped_total{reason="queue_full"} 1`,
		`mcp_audit_otel_queue_depth 1`,
		`mcp_audit_otel_queue_capacity 4`,
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

func TestPrometheusRecorderRecordsRPCErrorStatus(t *testing.T) {
	recorder, err := NewPrometheusRecorder(Config{Path: "/metrics", ToolLabels: true})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	recorder.RecordAuditEntry(audit.Entry{
		Direction: audit.DirectionServerToClient,
		Transport: "http",
		Method:    "tools/call",
		ToolName:  "", // exercises the "unknown" fallback
		Error:     &audit.RPCError{Code: -1, Message: "boom"},
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	resp := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(resp, req)
	body := resp.Body.String()

	if !strings.Contains(body, `status="rpc_error"`) {
		t.Fatalf("expected rpc_error status\n%s", body)
	}
	if !strings.Contains(body, `tool_name="unknown"`) {
		t.Fatalf("expected unknown tool_name fallback\n%s", body)
	}
	if !strings.Contains(body, `direction="server_to_client"`) {
		t.Fatalf("expected server_to_client direction\n%s", body)
	}
}

func TestPrometheusRecorderNormalizesEmptyDirection(t *testing.T) {
	recorder, err := NewPrometheusRecorder(Config{})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	recorder.RecordAuditEntry(audit.Entry{Direction: "", Transport: "stdio", Method: "ping"})

	req := httptest.NewRequest("GET", "/metrics", nil)
	resp := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(resp, req)
	if !strings.Contains(resp.Body.String(), `direction="unknown"`) {
		t.Fatalf("empty direction should normalize to unknown\n%s", resp.Body.String())
	}
}

func TestPrometheusRecorderFallsBackOnEmptyLabels(t *testing.T) {
	// Each Record* method falls back to "unknown" when a label is empty.
	// Exercising this branch closes the per-method coverage gap.
	recorder, err := NewPrometheusRecorder(Config{ToolLabels: true})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	recorder.RecordPolicyDecision("")
	recorder.RecordRateLimitRejection("", "")
	recorder.RecordHTTPUpstreamRetry("")
	recorder.RecordOTelExport("", 5*time.Millisecond, 1)
	recorder.RecordOTelDrop("", 1)

	req := httptest.NewRequest("GET", "/metrics", nil)
	resp := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(resp, req)
	body := resp.Body.String()

	for _, want := range []string{
		`mcp_audit_policy_decisions_total{action="unknown"}`,
		`mcp_audit_rate_limit_rejections_total{client_id="unknown",tool_name="unknown"}`,
		`mcp_audit_http_upstream_retries_total{reason="unknown"}`,
		`mcp_audit_otel_export_requests_total{status="unknown"}`,
		`mcp_audit_otel_spans_dropped_total{reason="unknown"}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in metrics output\n%s", want, body)
		}
	}
}

func TestPrometheusRecorderIgnoresZeroSpanRecords(t *testing.T) {
	// RecordOTelExport / RecordOTelDrop / RecordStorageWrite with spans/entries <= 0
	// should be no-ops. Verified by capturing the counter delta.
	recorder, err := NewPrometheusRecorder(Config{})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}

	recorder.RecordOTelExport("ok", time.Millisecond, 0)
	recorder.RecordOTelDrop("queue_full", 0)
	recorder.RecordStorageWrite("jsonl", "sync", "ok", time.Millisecond, 0)

	req := httptest.NewRequest("GET", "/metrics", nil)
	resp := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(resp, req)
	body := resp.Body.String()

	// Counters should not have been incremented to 1 (they are either absent
	// or present at 0, depending on label initialization).
	for _, forbidden := range []string{
		`mcp_audit_otel_export_requests_total{status="ok"} 1`,
		`mcp_audit_otel_spans_dropped_total{reason="queue_full"} 1`,
		`mcp_audit_storage_writes_total{backend="jsonl",mode="sync",status="ok"} 1`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("zero-span record should not increment counter: %q\n%s", forbidden, body)
		}
	}
}

func TestPrometheusRecorderIncludesGoAndProcessMetricsWhenEnabled(t *testing.T) {
	recorder, err := NewPrometheusRecorder(Config{
		IncludeGoMetrics:      true,
		IncludeProcessMetrics: true,
	})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	req := httptest.NewRequest("GET", "/metrics", nil)
	resp := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(resp, req)
	body := resp.Body.String()
	if !strings.Contains(body, "go_goroutines") {
		t.Fatal("expected go_goroutines metric when IncludeGoMetrics is set")
	}
	if !strings.Contains(body, "process_") {
		t.Fatal("expected process_* metric when IncludeProcessMetrics is set")
	}
}

// freePort returns a TCP port that was just bound and released; useful to
// avoid collisions in ListenAndServe tests.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func TestPrometheusRecorderListenAndServeShutdownsOnContextCancel(t *testing.T) {
	port := freePort(t)
	recorder, err := NewPrometheusRecorder(Config{Port: port, Path: "/metrics"})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- recorder.ListenAndServe(ctx) }()

	// Wait until the server accepts connections.
	deadline := time.Now().Add(2 * time.Second)
	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	for {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics server never became ready: %v", err)
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

func TestPrometheusRecorderListenAndServeReturnsErrorOnBindFailure(t *testing.T) {
	// Bind on 0.0.0.0:port (same as ListenAndServe's ":port") so the recorder
	// will collide. Binding on 127.0.0.1:port would not collide on macOS, so we
	// have to match the wildcard interface explicitly.
	blocker, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port

	recorder, err := NewPrometheusRecorder(Config{Port: port, Path: "/metrics"})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := recorder.ListenAndServe(ctx); err == nil {
		t.Fatal("expected error when port is already in use")
	}
}

func TestNoopRecorderHasZeroEffect(t *testing.T) {
	// Exercises every method on the noop recorder for coverage. Each call must
	// be a no-op and must not panic.
	r := Noop()
	r.RecordAuditEntry(audit.Entry{})
	r.RecordPolicyDecision("deny")
	r.RecordRateLimitRejection("c", "t")
	r.RecordHTTPUpstreamRetry("network")
	r.RecordStorageWrite("jsonl", "sync", "ok", time.Millisecond, 1)
	r.RecordOTelExport("ok", time.Millisecond, 1)
	r.RecordOTelDrop("queue_full", 1)
	r.SetOTelQueueDepth(1)
	r.SetOTelQueueCapacity(2)
	r.SetAsyncQueueDepth(3)
	r.SetAsyncQueueCapacity(4)
	r.RecordAsyncBackpressure()
	r.RecordAsyncBatch(5)
}
