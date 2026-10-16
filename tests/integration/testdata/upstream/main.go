package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var message request
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil || message.Method == "" || len(message.ID) == 0 {
			continue
		}
		result := `{"ok":true}`
		if message.Method == "initialize" {
			result = `{"protocolVersion":"2026-07-28","capabilities":{"tools":{}},"serverInfo":{"name":"integration-upstream","version":"1.0.0"}}`
		} else if message.Method == "tools/call" {
			result = `{"content":[{"type":"text","text":"ok"}]}`
		}
		fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n", message.ID, result)
	}
}
