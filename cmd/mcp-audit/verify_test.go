package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
)

func TestRunVerifyCommandJSONAfterPath(t *testing.T) {
	const secret = "command verification secret"
	t.Setenv("MCP_AUDIT_SIGNING_SECRET", secret)
	t.Setenv("AUDIT_SECRET", "wrong fallback secret")
	entry := commandTestEntry("signed")
	metadata, err := integrity.NewSigner(secret, "production").Sign(audit.IntegrityEntryV2(entry))
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	entry.Integrity = metadata
	path := writeCommandTestJSONL(t, entry)

	var stdout, stderr bytes.Buffer
	exitCode := runVerifyCommand([]string{path, "--json", "--key-id", "production"}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode JSON output: %v", err)
	}
	if result["verified"] != float64(1) || result["total"] != float64(1) {
		t.Fatalf("result = %v, want one verified entry", result)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunVerifyCommandUsesLegacyAuditSecret(t *testing.T) {
	const secret = "legacy environment secret"
	t.Setenv("MCP_AUDIT_SIGNING_SECRET", "")
	t.Setenv("AUDIT_SECRET", secret)
	entry := commandTestEntry("legacy")
	entry.Signature = audit.NewSigner(secret).Sign(entry)
	path := writeCommandTestJSONL(t, entry)

	var stdout, stderr bytes.Buffer
	exitCode := runVerifyCommand([]string{path}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "legacy: 1") {
		t.Fatalf("stdout = %q, want legacy count", stdout.String())
	}
}

func TestRunVerifyCommandReturnsOneForUnsignedEvidence(t *testing.T) {
	t.Setenv("MCP_AUDIT_SIGNING_SECRET", "")
	t.Setenv("AUDIT_SECRET", "")
	path := writeCommandTestJSONL(t, commandTestEntry("unsigned"))

	var stdout, stderr bytes.Buffer
	exitCode := runVerifyCommand([]string{path}, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stdout.String(), "unsigned: 1") {
		t.Fatalf("stdout = %q, want unsigned count", stdout.String())
	}
	if !strings.Contains(stderr.String(), "first error: entry unsigned: unsigned") {
		t.Fatalf("stderr = %q, want first error", stderr.String())
	}
}

func TestRunVerifyCommandReturnsTwoForUsageAndInputErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "missing path"},
		{name: "unknown option", args: []string{"--unknown"}},
		{name: "missing file", args: []string{filepath.Join(t.TempDir(), "missing.jsonl")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if exitCode := runVerifyCommand(tc.args, &stdout, &stderr); exitCode != 2 {
				t.Fatalf("exit code = %d, want 2; stderr = %q", exitCode, stderr.String())
			}
		})
	}
}

func commandTestEntry(id string) audit.Entry {
	return audit.Entry{
		ID:         id,
		Timestamp:  time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC),
		Direction:  audit.DirectionClientToServer,
		Transport:  "stdio",
		Method:     "ping",
		Params:     json.RawMessage(`{}`),
		DurationMs: 1,
		ClientID:   "client",
		ServerID:   "server",
	}
}

func writeCommandTestJSONL(t *testing.T, entry audit.Entry) string {
	t.Helper()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write JSONL: %v", err)
	}
	return path
}

func TestCheckpointCommandRoundTripAndExclusiveOutput(t *testing.T) {
	const secret = "checkpoint command test secret"
	t.Setenv("MCP_AUDIT_SIGNING_SECRET", secret)
	entry := commandTestEntry("checkpoint")
	entry.Integrity, _ = integrity.NewSigner(secret, integrity.DefaultKeyID).Sign(audit.IntegrityEntryV2(entry))
	path := writeCommandTestJSONL(t, entry)
	output := filepath.Join(t.TempDir(), "checkpoint.json")
	var stdout, stderr bytes.Buffer
	if code := runCheckpointCommand([]string{path, "--output", output, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("create: %d %s", code, &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runVerifyCommand([]string{path, "--checkpoint", output, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify: %d %s", code, &stderr)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{path, output} {
		if code := runCheckpointCommand([]string{path, "--output", target}, &stdout, &stderr); code != 2 {
			t.Fatalf("overwritten existing file: %s", target)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("source modified")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runVerifyCommand([]string{path, "--checkpoint", output}, &stdout, &stderr); code != 1 {
		t.Fatalf("empty checkpoint evidence exit=%d", code)
	}
}

func TestStrictCommandRejectsLegacyAndEmpty(t *testing.T) {
	t.Setenv("MCP_AUDIT_SIGNING_SECRET", "strict test secret")
	entry := commandTestEntry("legacy")
	entry.Signature = audit.NewSigner("strict test secret").Sign(entry)
	path := writeCommandTestJSONL(t, entry)
	var stdout, stderr bytes.Buffer
	if code := runVerifyCommand([]string{path, "--require-integrity-v2"}, &stdout, &stderr); code != 1 {
		t.Fatalf("legacy exit=%d", code)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runVerifyCommand([]string{path, "--require-integrity-v2"}, &stdout, &stderr); code != 1 {
		t.Fatalf("empty exit=%d", code)
	}
}

func TestCheckpointInputRejectsAmbiguousUnknownAndOversizeJSON(t *testing.T) {
	for _, raw := range []string{`{"version":1,"version":2}`, `{"unknown":1}`, strings.Repeat(" ", 65537)} {
		path := filepath.Join(t.TempDir(), "checkpoint.json")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCheckpoint(path); err == nil {
			t.Fatal("invalid checkpoint input accepted")
		}
	}
}
