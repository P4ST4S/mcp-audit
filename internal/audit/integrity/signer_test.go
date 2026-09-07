package integrity

import (
	"encoding/json"
	"errors"
	"testing"
)

func baseEntryV2() EntryV2 {
	return EntryV2{
		ID:               "01K39V3NN7R0AJPA4NPH7XQMYX",
		Timestamp:        "2026-08-24T09:10:11.123456789Z",
		AuditOperationID: "019d2f6e-47ad-75ad-b506-b7990d8c11ba",
		Outcome:          "success",
		Direction:        "server→client",
		Transport:        "http",
		Method:           "tools/call",
		RequestID:        "42",
		ToolName:         "read_file",
		Params:           json.RawMessage(`{"path":"/tmp","options":{"follow":false,"limit":10}}`),
		Result:           json.RawMessage(`{"content":"ok"}`),
		Error: &RPCErrorV2{
			Code:    -32000,
			Message: "upstream warning",
			Data:    json.RawMessage(`{"retryable":false}`),
		},
		DurationMS: 27,
		ClientID:   "claude-desktop",
		ServerID:   "filesystem",
	}
}

func cloneEntryV2(entry EntryV2) EntryV2 {
	cloned := entry
	cloned.Params = append(json.RawMessage(nil), entry.Params...)
	cloned.Result = append(json.RawMessage(nil), entry.Result...)
	if entry.Error != nil {
		errCopy := *entry.Error
		errCopy.Data = append(json.RawMessage(nil), entry.Error.Data...)
		cloned.Error = &errCopy
	}
	return cloned
}

func TestSignerProtectsEveryV2Field(t *testing.T) {
	signer := NewSigner("a sufficiently long test secret", "audit-prod")
	verifier := NewVerifier(map[string]string{"audit-prod": "a sufficiently long test secret"})
	base := baseEntryV2()
	metadata, err := signer.Sign(base)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*EntryV2)
	}{
		{"id", func(entry *EntryV2) { entry.ID = "different" }},
		{"timestamp", func(entry *EntryV2) { entry.Timestamp = "2026-08-24T09:10:12Z" }},
		{"audit operation ID", func(entry *EntryV2) { entry.AuditOperationID = "different" }},
		{"outcome", func(entry *EntryV2) { entry.Outcome = "timeout" }},
		{"direction", func(entry *EntryV2) { entry.Direction = "client→server" }},
		{"transport", func(entry *EntryV2) { entry.Transport = "stdio" }},
		{"method", func(entry *EntryV2) { entry.Method = "resources/read" }},
		{"request ID", func(entry *EntryV2) { entry.RequestID = "43" }},
		{"tool name", func(entry *EntryV2) { entry.ToolName = "write_file" }},
		{"params", func(entry *EntryV2) { entry.Params = json.RawMessage(`{"path":"/etc"}`) }},
		{"result", func(entry *EntryV2) { entry.Result = json.RawMessage(`{"content":"changed"}`) }},
		{"error code", func(entry *EntryV2) { entry.Error.Code = -32001 }},
		{"error message", func(entry *EntryV2) { entry.Error.Message = "changed" }},
		{"error data", func(entry *EntryV2) { entry.Error.Data = json.RawMessage(`{"retryable":true}`) }},
		{"duration", func(entry *EntryV2) { entry.DurationMS++ }},
		{"client ID", func(entry *EntryV2) { entry.ClientID = "other-client" }},
		{"server ID", func(entry *EntryV2) { entry.ServerID = "other-server" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneEntryV2(base)
			tc.mutate(&mutated)
			if err := verifier.Verify(mutated, metadata); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("verify error = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestCanonicalizationIgnoresObjectOrderAndWhitespace(t *testing.T) {
	signer := NewSigner("test secret", DefaultKeyID)
	verifier := NewVerifier(map[string]string{DefaultKeyID: "test secret"})
	entry := baseEntryV2()
	metadata, err := signer.Sign(entry)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	equivalent := cloneEntryV2(entry)
	equivalent.Params = json.RawMessage(`{
  "options": { "limit": 10, "follow": false },
  "path": "/tmp"
}`)
	if err := verifier.Verify(equivalent, metadata); err != nil {
		t.Fatalf("semantically equivalent JSON should verify: %v", err)
	}
}

func TestCanonicalizationRejectsDuplicateObjectKeys(t *testing.T) {
	entry := baseEntryV2()
	entry.Params = json.RawMessage(`{"path":"/tmp","path":"/etc"}`)
	if _, err := Canonicalize(entry); err == nil {
		t.Fatal("expected duplicate JSON key to be rejected")
	}
}

func TestCanonicalizationRejectsUnsafeDurationInteger(t *testing.T) {
	entry := baseEntryV2()
	entry.DurationMS = maxJCSSafeInteger + 1
	if _, err := Canonicalize(entry); err == nil {
		t.Fatal("expected unsafe duration integer to be rejected")
	}
}

func TestVerifierReportsUnsupportedMetadata(t *testing.T) {
	entry := baseEntryV2()
	signer := NewSigner("test secret", DefaultKeyID)
	metadata, err := signer.Sign(entry)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifier := NewVerifier(map[string]string{DefaultKeyID: "test secret"})

	unsupportedVersion := *metadata
	unsupportedVersion.Version = 3
	if err := verifier.Verify(entry, &unsupportedVersion); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("version error = %v, want ErrUnsupportedVersion", err)
	}

	unsupportedAlgorithm := *metadata
	unsupportedAlgorithm.Algorithm = "ed25519"
	if err := verifier.Verify(entry, &unsupportedAlgorithm); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("algorithm error = %v, want ErrUnsupportedAlgorithm", err)
	}

	unknownKey := *metadata
	unknownKey.KeyID = "missing"
	if err := verifier.Verify(entry, &unknownKey); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("key error = %v, want ErrUnknownKey", err)
	}
}

func TestSignerDisabledWithoutSecret(t *testing.T) {
	signer := NewSigner("", DefaultKeyID)
	if signer.Enabled() {
		t.Fatal("empty secret should disable signer")
	}
	metadata, err := signer.Sign(baseEntryV2())
	if err != nil {
		t.Fatalf("disabled sign: %v", err)
	}
	if metadata != nil {
		t.Fatalf("disabled signer metadata = %#v, want nil", metadata)
	}
}
