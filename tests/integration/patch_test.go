//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/audit/storage"
)

func TestHTTPBinaryHistoricalSQLiteSearch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := storage.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]audit.Entry, 10001)
	for i := range entries {
		entries[i] = audit.Entry{ID: fmt.Sprint(i), Timestamp: time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC), ClientID: "recent", Direction: audit.DirectionClientToServer, ToolName: "read"}
	}
	entries[0].ClientID = "target"
	if err := store.AppendBatch(entries); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	proxyPort, dashboardPort := freePort(t), freePort(t)
	config := fmt.Sprintf(`proxy:
  transport: http
  upstream: http://127.0.0.1:1
  port: %d
audit:
  storage: sqlite
  sqlite_path: %q
  sign: true
dashboard:
  enabled: true
  bind_address: 127.0.0.1
  port: %d
metrics:
  enabled: false
`, proxyPort, path, dashboardPort)
	command, stderr := startHTTPProxy(t, writeConfig(t, config), proxyPort, nil)
	defer stopProcess(t, command, stderr)
	waitForPort(t, dashboardPort, command, stderr)
	response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/entries?client_id=target", dashboardPort))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var found []audit.Entry
	if err := json.NewDecoder(response.Body).Decode(&found); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(found) != 1 || found[0].ID != "0" {
		t.Fatalf("status=%d entries=%+v", response.StatusCode, found)
	}
}

func TestHTTPBinaryTimeoutTelemetryAndSignedEvidence(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		<-r.Context().Done()
	}))
	defer upstream.Close()
	type span struct {
		Status struct {
			Code int `json:"code"`
		} `json:"status"`
		Attributes []struct {
			Key   string `json:"key"`
			Value struct {
				StringValue string `json:"stringValue"`
			} `json:"value"`
		} `json:"attributes"`
	}
	spans := make(chan span, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []span `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad payload", 400)
			return
		}
		for _, resource := range payload.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				for _, s := range scope.Spans {
					spans <- s
				}
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer collector.Close()
	proxyPort, metricsPort := freePort(t), freePort(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	config := fmt.Sprintf(`proxy:
  transport: http
  upstream: %q
  upstream_timeout_ms: 50
  port: %d
audit:
  storage: jsonl
  path: %q
  sign: true
metrics:
  enabled: true
  port: %d
dashboard:
  enabled: false
otel:
  enabled: true
  endpoint: %q
  batch_size: 1
  flush_interval_ms: 10
`, upstream.URL, proxyPort, path, metricsPort, collector.URL)
	command, stderr := startHTTPProxy(t, writeConfig(t, config), proxyPort, nil)
	defer stopProcess(t, command, stderr)
	response := postMCP(t, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/mcp", proxyPort), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`, nil)
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d", response.StatusCode)
	}
	waitForPort(t, metricsPort, command, stderr)
	metrics, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(metrics.Body)
	metrics.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `mcp_audit_entries_total{direction="server_to_client",method="tools/call",status="timeout",transport="http"} 1`) {
		t.Fatalf("timeout not recorded in metrics: %s", raw)
	}
	select {
	case s := <-spans:
		if s.Status.Code != 2 {
			t.Fatalf("OTLP status=%d", s.Status.Code)
		}
		found := false
		for _, attr := range s.Attributes {
			if attr.Key == "error.type" && attr.Value.StringValue == "timeout" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing timeout error.type: %+v", s.Attributes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout span not exported")
	}
	verify := exec.Command(binaryPath, "verify", path, "--json")
	entries := readAuditEntries(t, path)
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeTimeout || entries[0].Integrity == nil {
		t.Fatalf("timeout audit evidence = %+v", entries)
	}
	verify.Env = commandEnv(map[string]string{"MCP_AUDIT_SIGNING_SECRET": signingSecret}, "AUDIT_SECRET")
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("verify timeout audit: %v\n%s", err, output)
	}
}
