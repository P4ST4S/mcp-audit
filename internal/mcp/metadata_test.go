package mcp

import (
	"net/http"
	"reflect"
	"testing"
)

func TestInspectRequestClassifiesOperationFamilies(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		method     string
		entityName string
		kind       RequestKind
	}{
		{name: "tool call", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file"}}`, method: "tools/call", entityName: "delete_file", kind: RequestKindTools},
		{name: "resource read", body: `{"jsonrpc":"2.0","id":"r1","method":"resources/read","params":{"uri":"file:///tmp/a"}}`, method: "resources/read", entityName: "file:///tmp/a", kind: RequestKindResources},
		{name: "prompt get", body: `{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"review"}}`, method: "prompts/get", entityName: "review", kind: RequestKindPrompts},
		{name: "completion", body: `{"jsonrpc":"2.0","id":3,"method":"completion/complete","params":{"ref":{"name":"review"}}}`, method: "completion/complete", entityName: "review", kind: RequestKindCompletion},
		{name: "logging", body: `{"jsonrpc":"2.0","method":"logging/setLevel","params":{"level":"debug"}}`, method: "logging/setLevel", kind: RequestKindLogging},
		{name: "discover", body: `{"jsonrpc":"2.0","id":4,"method":"server/discover"}`, method: "server/discover", kind: RequestKindDiscovery},
		{name: "task", body: `{"jsonrpc":"2.0","id":5,"method":"tasks/get","params":{"name":"task-1"}}`, method: "tasks/get", entityName: "task-1", kind: RequestKindTasks},
		{name: "extension", body: `{"jsonrpc":"2.0","id":6,"method":"extensions/acme.run","params":{"name":"job"}}`, method: "extensions/acme.run", entityName: "job", kind: RequestKindExtensions},
		{name: "unknown", body: `{"jsonrpc":"2.0","id":7,"method":"ping"}`, method: "ping", kind: RequestKindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := InspectRequest(nil, []byte(tc.body))
			if err != nil {
				t.Fatalf("inspect request: %v", err)
			}
			if metadata.Method != tc.method || metadata.Name != tc.entityName || metadata.Kind != tc.kind {
				t.Fatalf("metadata = %#v", metadata)
			}
		})
	}
}

func TestInspectRequestValidatesHeadersAgainstBody(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"delete_file","_meta":{"protocolRevision":"2026-07-28"}}}`)
	headers := http.Header{
		HeaderMethod:          {"tools/call"},
		HeaderName:            {"delete_file"},
		HeaderProtocolVersion: {"2026-07-28"},
	}
	metadata, err := InspectRequest(headers, body)
	if err != nil {
		t.Fatalf("inspect request: %v", err)
	}
	want := RequestMetadata{
		ProtocolRevision: Protocol20260728,
		Method:           "tools/call",
		Name:             "delete_file",
		RequestID:        "42",
		Kind:             RequestKindTools,
	}
	if !reflect.DeepEqual(metadata, want) {
		t.Fatalf("metadata = %#v, want %#v", metadata, want)
	}
}

func TestInspectRequestRejectsMetadataMismatch(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file"}}`)
	cases := []http.Header{
		{HeaderMethod: {"resources/read"}},
		{HeaderName: {"read_file"}},
		{HeaderProtocolVersion: {"2026-07-28", "2025-11-25"}},
		{HeaderProtocolVersion: {"2099-01-01"}},
	}
	for _, headers := range cases {
		if _, err := InspectRequest(headers, body); err == nil {
			t.Fatalf("expected mismatch for headers %#v", headers)
		}
	}
}

func TestInspectRequestDetectsRevision(t *testing.T) {
	cases := []struct {
		name string
		body string
		want ProtocolRevision
	}{
		{name: "legacy fallback", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, want: ProtocolLegacy20251125},
		{name: "legacy initialize", body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`, want: ProtocolLegacy20251125},
		{name: "self contained meta", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"protocolVersion":"2026-07-28"}}}`, want: Protocol20260728},
		{name: "discover", body: `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`, want: Protocol20260728},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := InspectRequest(nil, []byte(tc.body))
			if err != nil {
				t.Fatalf("inspect request: %v", err)
			}
			if metadata.ProtocolRevision != tc.want {
				t.Fatalf("revision = %q, want %q", metadata.ProtocolRevision, tc.want)
			}
		})
	}
}

func TestInspectRequestDoesNotMutateBody(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"requestState":{"round":2},"cache":{"ttl":60}}}`)
	want := append([]byte(nil), body...)
	if _, err := InspectRequest(nil, body); err != nil {
		t.Fatalf("inspect request: %v", err)
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("body mutated: %s", body)
	}
}
