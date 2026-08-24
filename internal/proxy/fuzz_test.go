package proxy

import (
	"encoding/json"
	"testing"
)

func FuzzJSONRPCDecodeAndErrorResponse(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`))
	f.Add([]byte(`[{"jsonrpc":"2.0","id":"a","method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":{"nested":true},"method":"resources/read"}`))
	f.Add([]byte(`null`))
	f.Add([]byte("\x00\xff"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		messages, err := decodeMessages(raw)
		if err != nil {
			return
		}
		for _, message := range messages {
			response := buildErrorResponse(message.ID, nil)
			if !json.Valid(response) {
				t.Fatalf("invalid JSON error response: %q", response)
			}
			_ = toolNameFromParams(message.Method, message.Params)
			_ = jsonRPCID(message.ID)
		}
	})
}

func FuzzHTTPAccessListNormalization(f *testing.F) {
	f.Add("https://example.com", "localhost")
	f.Add("https://example.com:443", "127.0.0.1:4422")
	f.Add("http://[::1]:80", "[::1]")
	f.Add("https://user@example.com", "example.com/path")
	f.Add(" https://example.com", "example.com\x00")
	f.Add("file:///etc/passwd", "example.com:bad")

	f.Fuzz(func(t *testing.T, origin, host string) {
		normalizedOrigin, originErr := normalizeOrigin(origin)
		if originErr == nil {
			again, err := normalizeOrigin(normalizedOrigin)
			if err != nil || again != normalizedOrigin {
				t.Fatalf("origin normalization is not idempotent: %q -> %q -> %q (%v)", origin, normalizedOrigin, again, err)
			}
		}
		normalizedHost, hostErr := normalizeHostname(host)
		if hostErr == nil {
			again, err := normalizeHostname(normalizedHost)
			if err != nil || again != normalizedHost {
				t.Fatalf("host normalization is not idempotent: %q -> %q -> %q (%v)", host, normalizedHost, again, err)
			}
		}
		_ = ValidateHTTPAccessLists([]string{origin}, []string{host})
	})
}
