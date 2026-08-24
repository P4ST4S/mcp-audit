package integrity

import (
	"encoding/json"
	"errors"
	"testing"
)

func FuzzIntegrityV2RoundTrip(f *testing.F) {
	f.Add("tools/call", "client", []byte(`{"name":"read_file","arguments":{"path":"/tmp/a"}}`), []byte(`{"ok":true}`), []byte(`{"retryable":false}`), int64(17))
	f.Add("resources/read", "client", []byte(`{"uri":"file:///tmp/a","n":9007199254740991}`), []byte(`null`), []byte(`null`), int64(0))
	f.Add("prompts/get", "客户端", []byte(`{"name":"résumé"}`), []byte(`{"text":"é"}`), []byte(`{"nested":[1,2,3]}`), int64(-1))
	f.Add("tools/call", "client", []byte(`{"duplicate":1,"duplicate":2}`), []byte(`{}`), []byte(`{}`), int64(1))

	f.Fuzz(func(t *testing.T, method, clientID string, params, result, errorData []byte, durationMS int64) {
		if !json.Valid(params) || !json.Valid(result) || !json.Valid(errorData) {
			return
		}
		entry := EntryV2{
			ID:         "01K39V3NN7R0AJPA4NPH7XQMYX",
			Timestamp:  "2026-08-24T09:10:11.123456789Z",
			Direction:  "client→server",
			Transport:  "http",
			Method:     method,
			Params:     append(json.RawMessage(nil), params...),
			Result:     append(json.RawMessage(nil), result...),
			Error:      &RPCErrorV2{Code: -32000, Message: "upstream", Data: append(json.RawMessage(nil), errorData...)},
			DurationMS: durationMS,
			ClientID:   clientID,
			ServerID:   "server",
		}
		signer := NewSigner("fuzz regression signing secret", "fuzz")
		metadata, err := signer.Sign(entry)
		if err != nil {
			return
		}
		verifier := NewVerifier(map[string]string{"fuzz": "fuzz regression signing secret"})
		if err := verifier.Verify(entry, metadata); err != nil {
			t.Fatalf("fresh signature did not verify: %v", err)
		}
		entry.ClientID += "\x00mutated"
		if err := verifier.Verify(entry, metadata); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("mutated signed entry error = %v, want invalid signature", err)
		}
	})
}
