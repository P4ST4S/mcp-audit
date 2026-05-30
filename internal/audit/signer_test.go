package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSignerDisabledWhenSecretEmpty(t *testing.T) {
	s := NewSigner("")
	if s.Enabled() {
		t.Fatal("signer with empty secret should be disabled")
	}
	if got := s.Sign(Entry{ID: "x"}); got != "" {
		t.Fatalf("disabled signer should return empty signature, got %q", got)
	}
}

func TestSignerNilReceiverDisabled(t *testing.T) {
	var s *Signer
	if s.Enabled() {
		t.Fatal("nil signer should not be enabled")
	}
}

func TestSignerEnabledWithSecret(t *testing.T) {
	s := NewSigner("hunter2")
	if !s.Enabled() {
		t.Fatal("signer with non-empty secret should be enabled")
	}
}

func TestSignerProducesDeterministicSignature(t *testing.T) {
	s := NewSigner("hunter2")
	entry := Entry{
		ID:        "01HY8G6Y8S6W9K6ZD7VJ4Q8X4R",
		Timestamp: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		Method:    "tools/call",
		ToolName:  "read_file",
		Params:    json.RawMessage(`{"path":"/tmp"}`),
	}
	first := s.Sign(entry)
	second := s.Sign(entry)
	if first == "" {
		t.Fatal("enabled signer returned empty signature")
	}
	if first != second {
		t.Fatalf("signature not deterministic: %q vs %q", first, second)
	}
}

func TestSignerSignatureChangesWhenAnySignedFieldChanges(t *testing.T) {
	s := NewSigner("hunter2")
	base := Entry{
		ID:        "01HY8G6Y8S6W9K6ZD7VJ4Q8X4R",
		Timestamp: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		Method:    "tools/call",
		ToolName:  "read_file",
		Params:    json.RawMessage(`{"path":"/tmp"}`),
	}
	baseSig := s.Sign(base)

	cases := []struct {
		name   string
		mutate func(*Entry)
	}{
		{"id changed", func(e *Entry) { e.ID = "different-id" }},
		{"timestamp changed", func(e *Entry) { e.Timestamp = e.Timestamp.Add(time.Second) }},
		{"method changed", func(e *Entry) { e.Method = "resources/read" }},
		{"tool name changed", func(e *Entry) { e.ToolName = "write_file" }},
		{"params changed", func(e *Entry) { e.Params = json.RawMessage(`{"path":"/other"}`) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			tc.mutate(&mutated)
			got := s.Sign(mutated)
			if got == baseSig {
				t.Fatalf("signature did not change after %q", tc.name)
			}
		})
	}
}

func TestSignerSignatureIgnoresUnsignedFields(t *testing.T) {
	// Result, Error, Direction, ClientID, ServerID, DurationMs are intentionally
	// not part of the signature. Changing them must not affect the signature.
	s := NewSigner("hunter2")
	base := Entry{
		ID:        "01HY8G6Y8S6W9K6ZD7VJ4Q8X4R",
		Timestamp: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		Method:    "tools/call",
		ToolName:  "read_file",
		Params:    json.RawMessage(`{"path":"/tmp"}`),
	}
	baseSig := s.Sign(base)

	mutated := base
	mutated.Result = json.RawMessage(`{"different":"result"}`)
	mutated.Error = &RPCError{Code: -32603, Message: "internal error"}
	mutated.Direction = DirectionServerToClient
	mutated.ClientID = "other-client"
	mutated.ServerID = "other-server"
	mutated.DurationMs = 999

	if s.Sign(mutated) != baseSig {
		t.Fatal("signature changed when only unsigned fields were modified")
	}
}

func TestSignerTimestampNormalizedToUTC(t *testing.T) {
	// Two timestamps representing the same instant in different zones
	// must produce the same signature.
	s := NewSigner("hunter2")
	utc := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Skipf("Europe/Paris zone unavailable: %v", err)
	}
	sameInstant := utc.In(paris)

	entryUTC := Entry{ID: "x", Timestamp: utc, Method: "ping"}
	entryParis := Entry{ID: "x", Timestamp: sameInstant, Method: "ping"}

	if s.Sign(entryUTC) != s.Sign(entryParis) {
		t.Fatal("signature should be timezone-independent for the same instant")
	}
}

func TestSignerDifferentSecretsProduceDifferentSignatures(t *testing.T) {
	entry := Entry{ID: "x", Timestamp: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC), Method: "ping"}
	first := NewSigner("secret-a").Sign(entry)
	second := NewSigner("secret-b").Sign(entry)
	if first == second {
		t.Fatal("different secrets produced the same signature")
	}
}

func TestSignerOutputIsHexEncoded(t *testing.T) {
	s := NewSigner("hunter2")
	entry := Entry{ID: "x", Timestamp: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC), Method: "ping"}
	sig := s.Sign(entry)
	if len(sig) != 64 {
		t.Fatalf("HMAC-SHA256 hex output must be 64 chars, got %d", len(sig))
	}
	for _, c := range sig {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			t.Fatalf("signature contains non-hex character %q in %q", c, sig)
		}
	}
}
