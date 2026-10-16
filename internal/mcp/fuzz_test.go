package mcp

import (
	"bytes"
	"net/http"
	"testing"
)

func FuzzInspectRequest(f *testing.F) {
	seeds := []struct {
		method   string
		name     string
		revision string
		body     string
	}{
		{"tools/call", "read_file", "2026-07-28", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`},
		{"resources/read", "file:///tmp/a", "2025-06-18", `{"jsonrpc":"2.0","id":"r1","method":"resources/read","params":{"uri":"file:///tmp/a"}}`},
		{"", "", "", `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`},
		{"tools/call", "different", "2026-07-28", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"actual"}}`},
		{"", "", "2026-07-28", ""},
		{"tools/list", "", "2026-07-28", `{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/list"}`},
		{"tools/list", "", "2026-07-28", `{"jsonrpc":"2.0","method":"tools/list"} trailing`},
	}
	for _, seed := range seeds {
		f.Add(seed.method, seed.name, seed.revision, []byte(seed.body))
	}

	f.Fuzz(func(t *testing.T, method, name, revision string, body []byte) {
		original := append([]byte(nil), body...)
		headers := make(http.Header)
		if method != "" {
			headers.Set(HeaderMethod, method)
		}
		if name != "" {
			headers.Set(HeaderName, name)
		}
		if revision != "" {
			headers.Set(HeaderProtocolVersion, revision)
		}
		_, _ = InspectRequest(headers, body)
		if !bytes.Equal(body, original) {
			t.Fatal("InspectRequest mutated the request body")
		}
	})
}

func FuzzDecodeMessages(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	f.Add([]byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"method":"tools/call","params":{"name":"x","name":"y"}}`))
	f.Add([]byte("\x00\xff{}"))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}{}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		messages, err := DecodeMessages(raw)
		if err != nil {
			return
		}
		if len(messages) == 0 || len(messages) > maxBatchMessages {
			t.Fatalf("successful decode returned %d messages", len(messages))
		}
		for _, message := range messages {
			if message.Method == "" {
				t.Fatal("successful decode returned an empty method")
			}
		}
	})
}
