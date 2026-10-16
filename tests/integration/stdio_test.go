//go:build integration

package integration_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

func TestStdioBinaryHappyPathRedactionAndGracefulShutdown(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	configPath := writeStdioConfig(t, auditPath, "")
	command, stdin, scanner, stderr := startStdioProxy(t, configPath)

	sendJSONRPC(t, stdin, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"integration","version":"1.0"}}}`)
	assertResponseID(t, scanner, 1)
	sendJSONRPC(t, stdin, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello","token":"top-secret"}}}`)
	assertResponseID(t, scanner, 2)
	stopProcess(t, command, stderr)

	entries := readAuditEntries(t, auditPath)
	var toolEntry *audit.Entry
	for index := range entries {
		if entries[index].Method == "tools/call" {
			toolEntry = &entries[index]
		}
	}
	if toolEntry == nil {
		t.Fatalf("tools/call audit entry not found: %#v", entries)
	}
	if toolEntry.Outcome != audit.OutcomeSuccess || toolEntry.Integrity == nil || toolEntry.Signature == "" {
		t.Fatalf("terminal signed entry = %#v", toolEntry)
	}
	if !bytes.Contains(toolEntry.Params, []byte(`"token":"[REDACTED]"`)) || bytes.Contains(toolEntry.Params, []byte("top-secret")) {
		t.Fatalf("redacted params = %s", toolEntry.Params)
	}

	verify := exec.Command(binaryPath, "verify", auditPath, "--json")
	verify.Env = commandEnv(map[string]string{"MCP_AUDIT_SIGNING_SECRET": signingSecret}, "AUDIT_SECRET")
	output, err := verify.CombinedOutput()
	if err != nil {
		t.Fatalf("verify audit artifact: %v\n%s", err, output)
	}
	var result struct {
		Verified int `json:"verified"`
		Invalid  int `json:"invalid"`
		Unsigned int `json:"unsigned"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode verification output: %v\n%s", err, output)
	}
	if result.Verified < 2 || result.Invalid != 0 || result.Unsigned != 0 {
		t.Fatalf("verification result = %+v", result)
	}
}

func TestStdioBinaryPolicyDeny(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	policy := `policy:
  enabled: true
  default_action: allow
  scope: all_operations
  rules:
    - action: deny
      method: tools/call
      name: delete_file
      reason: blocked by integration policy
`
	configPath := writeStdioConfig(t, auditPath, policy)
	command, stdin, scanner, stderr := startStdioProxy(t, configPath)
	sendJSONRPC(t, stdin, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","arguments":{}}}`)
	response := scanResponse(t, scanner)
	errorObject := response["error"].(map[string]any)
	if errorObject["code"] != float64(-32030) {
		t.Fatalf("response = %#v", response)
	}
	_ = stdin.Close()
	waitProcess(t, command, stderr)

	entries := readAuditEntries(t, auditPath)
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeDenied || entries[0].Error == nil || entries[0].Error.Code != -32030 {
		t.Fatalf("policy audit entries = %#v", entries)
	}
}

func TestStdioBinaryRateLimitsSixtyFirstCall(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	configPath := writeStdioConfig(t, auditPath, "")
	command, stdin, scanner, stderr := startStdioProxy(t, configPath)
	for id := 1; id <= 61; id++ {
		sendJSONRPC(t, stdin, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{}}}`, id))
		response := scanResponse(t, scanner)
		if id <= 60 {
			if response["result"] == nil {
				t.Fatalf("request %d was rejected: %#v", id, response)
			}
			continue
		}
		errorObject := response["error"].(map[string]any)
		if errorObject["code"] != float64(-32029) {
			t.Fatalf("61st response = %#v", response)
		}
	}
	_ = stdin.Close()
	waitProcess(t, command, stderr)

	entries := readAuditEntries(t, auditPath)
	if len(entries) != 61 || entries[len(entries)-1].Outcome != audit.OutcomeRateLimited {
		t.Fatalf("rate-limit audit count/outcome = %d/%q", len(entries), entries[len(entries)-1].Outcome)
	}
}

func TestBinaryFailsClosedBeforeStartingUpstream(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(directory, "started")
	upstream := fmt.Sprintf("touch %s", marker)
	config := fmt.Sprintf(`proxy:
  transport: stdio
  upstream: %q
audit:
  sign: true
dashboard:
  enabled: false
metrics:
  enabled: false
`, upstream)
	configPath := writeConfig(t, config)
	command := exec.Command(binaryPath, "--config", configPath, "--log-level", "error")
	command.Env = commandEnv(nil, "MCP_AUDIT_SIGNING_SECRET", "AUDIT_SECRET")
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("signing is enabled but no signing secret")) {
		t.Fatalf("exit error/output = %v/%s", err, output)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("upstream marker exists or stat failed: %v", err)
	}
}

func TestVerifySQLiteArtifactProducedByBinary(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "audit.db")
	config := fmt.Sprintf(`proxy:
  transport: stdio
  upstream: %q
audit:
  storage: sqlite
  sqlite_path: %q
  sign: true
dashboard:
  enabled: false
metrics:
  enabled: false
`, upstreamPath, databasePath)
	command, stdin, _, stderr := startStdioProxy(t, writeConfig(t, config))
	sendJSONRPC(t, stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	_ = stdin.Close()
	waitProcess(t, command, stderr)

	verify := exec.Command(binaryPath, "verify", databasePath, "--format", "sqlite", "--json")
	verify.Env = commandEnv(map[string]string{"MCP_AUDIT_SIGNING_SECRET": signingSecret}, "AUDIT_SECRET")
	output, err := verify.CombinedOutput()
	if err != nil {
		t.Fatalf("verify SQLite artifact: %v\n%s", err, output)
	}
	var result struct {
		Verified int `json:"verified"`
		Invalid  int `json:"invalid"`
	}
	if err := json.Unmarshal(output, &result); err != nil || result.Verified != 1 || result.Invalid != 0 {
		t.Fatalf("SQLite verification = %+v, err %v\n%s", result, err, output)
	}
}

func writeStdioConfig(t *testing.T, auditPath, extra string) string {
	t.Helper()
	config := fmt.Sprintf(`proxy:
  transport: stdio
  upstream: %q
  client_id: integration-client
  server_id: integration-upstream
audit:
  storage: jsonl
  path: %q
  sign: true
middleware:
  rate_limit:
    enabled: true
    requests_per_minute: 60
  redact:
    enabled: true
    patterns: [token, secret, authorization, bearer]
dashboard:
  enabled: false
metrics:
  enabled: false
%s`, upstreamPath, auditPath, extra)
	return writeConfig(t, config)
}

func startStdioProxy(t *testing.T, configPath string) (*exec.Cmd, *os.File, *bufio.Scanner, *lockedBuffer) {
	t.Helper()
	command := exec.Command(binaryPath, "--config", configPath, "--log-level", "error")
	command.Env = commandEnv(map[string]string{"MCP_AUDIT_SIGNING_SECRET": signingSecret}, "AUDIT_SECRET")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr := newLockedBuffer()
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	t.Cleanup(func() {
		if command.Process != nil && command.ProcessState == nil {
			_ = command.Process.Kill()
		}
	})
	return command, stdin.(*os.File), bufio.NewScanner(stdout), stderr
}

func sendJSONRPC(t *testing.T, stdin *os.File, message string) {
	t.Helper()
	if _, err := fmt.Fprintln(stdin, message); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

func assertResponseID(t *testing.T, scanner *bufio.Scanner, id int) {
	t.Helper()
	response := scanResponse(t, scanner)
	if response["id"] != float64(id) || response["result"] == nil {
		t.Fatalf("response = %#v, want id %d result", response, id)
	}
}

func scanResponse(t *testing.T, scanner *bufio.Scanner) map[string]any {
	t.Helper()
	if !scanner.Scan() {
		t.Fatalf("read response: %v", scanner.Err())
	}
	var response map[string]any
	if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v\n%s", err, scanner.Bytes())
	}
	return response
}

func waitProcess(t *testing.T, command *exec.Cmd, stderr *lockedBuffer) {
	t.Helper()
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		if err != nil {
			t.Fatalf("process exit: %v\n%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("process did not exit: %s", stderr.String())
	}
}

func readAuditEntries(t *testing.T, path string) []audit.Entry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var entries []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var entry audit.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode audit entry: %v\n%s", err, line)
		}
		entries = append(entries, entry)
	}
	return entries
}
