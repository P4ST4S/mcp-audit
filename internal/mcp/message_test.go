package mcp

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeMessagesAcceptsSingleAndBatch(t *testing.T) {
	single, err := DecodeMessages([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil || len(single) != 1 || single[0].Method != "tools/list" {
		t.Fatalf("single = %#v, err = %v", single, err)
	}
	batch, err := DecodeMessages([]byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"logging/setLevel"}]`))
	if err != nil || len(batch) != 2 {
		t.Fatalf("batch = %#v, err = %v", batch, err)
	}
}

func TestDecodeMessagesRejectsInvalidPayloads(t *testing.T) {
	cases := []string{
		``,
		`null`,
		`[]`,
		`{"jsonrpc":"2.0","id":1}`,
		`{"jsonrpc":"2.0","method":"ping"} {"method":"ping"}`,
		`[1]`,
	}
	for _, body := range cases {
		if _, err := DecodeMessages([]byte(body)); err == nil {
			t.Fatalf("expected error for %q", body)
		}
	}
}

func TestDecodeMessagesBoundsBatchCardinality(t *testing.T) {
	items := make([]string, maxBatchMessages+1)
	for index := range items {
		items[index] = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"ping"}`, index)
	}
	body := "[" + strings.Join(items, ",") + "]"
	if _, err := DecodeMessages([]byte(body)); err == nil {
		t.Fatal("expected oversized batch error")
	}
}

func TestInspectRequestRejectsBatchHeaders(t *testing.T) {
	body := []byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"prompts/list"}]`)
	if _, err := InspectRequest(nil, body); err == nil {
		t.Fatal("expected batch inspection error")
	}
}
