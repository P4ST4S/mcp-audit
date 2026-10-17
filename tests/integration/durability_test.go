//go:build integration

package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestHTTPBinaryDurableAsyncAndCheckpoint(t *testing.T) {
	for _, backend := range []string{"jsonl", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
			}))
			defer upstream.Close()
			port := freePort(t)
			path := filepath.Join(t.TempDir(), "audit."+map[string]string{"jsonl": "jsonl", "sqlite": "db"}[backend])
			config := fmt.Sprintf(`proxy:
  transport: http
  bind_address: 127.0.0.1
  upstream: %q
  port: %d
audit:
  storage: %s
  path: %q
  sqlite_path: %q
  sign: true
  durable: true
  async:
    enabled: true
dashboard:
  enabled: false
metrics:
  enabled: false
`, upstream.URL, port, backend, path, path)
			command, stderr := startHTTPProxy(t, writeConfig(t, config), port, nil)
			defer stopProcess(t, command, stderr)
			response := postMCP(t, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/mcp", port), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`, nil)
			_, err := io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 {
				t.Fatalf("response=%d error=%v", response.StatusCode, err)
			}
			stopProcess(t, command, stderr)
			if calls.Load() != 1 {
				t.Fatalf("tools/call executed %d times", calls.Load())
			}
			checkpoint := filepath.Join(t.TempDir(), "checkpoint.json")
			for _, args := range [][]string{{"checkpoint", path, "--output", checkpoint}, {"verify", path, "--require-integrity-v2", "--checkpoint", checkpoint, "--json"}} {
				verify := exec.Command(binaryPath, args...)
				verify.Env = commandEnv(map[string]string{"MCP_AUDIT_SIGNING_SECRET": signingSecret}, "AUDIT_SECRET")
				if output, err := verify.CombinedOutput(); err != nil {
					t.Fatalf("%v: %v\n%s", args, err, output)
				}
			}
		})
	}
}

func TestStdioBinaryDurableAsync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	config := fmt.Sprintf(`proxy:
  transport: stdio
  upstream: %q
audit:
  storage: jsonl
  path: %q
  sign: true
  durable: true
  async:
    enabled: true
dashboard:
  enabled: false
metrics:
  enabled: false
`, upstreamPath, path)
	command, stdin, scanner, stderr := startStdioProxy(t, writeConfig(t, config))
	defer stopProcess(t, command, stderr)
	sendJSONRPC(t, stdin, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`)
	assertResponseID(t, scanner, 1)
	stopProcess(t, command, stderr)
	entries := readAuditEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("entries=%d", len(entries))
	}
	verify := exec.Command(binaryPath, "verify", path, "--require-integrity-v2")
	verify.Env = commandEnv(map[string]string{"MCP_AUDIT_SIGNING_SECRET": signingSecret}, "AUDIT_SECRET")
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("strict verify: %v\n%s", err, output)
	}
}
