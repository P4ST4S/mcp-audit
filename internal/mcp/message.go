package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const maxBatchMessages = 1024

// Message contains the JSON-RPC request fields needed for gateway inspection.
type Message struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// DecodeMessages parses a single JSON-RPC request or a bounded request batch.
func DecodeMessages(raw []byte) ([]Message, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var payload json.RawMessage
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("mcp: decode request: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 {
		return nil, fmt.Errorf("mcp: request is empty")
	}
	if payload[0] != '[' {
		message, err := decodeMessage(payload)
		if err != nil {
			return nil, err
		}
		return []Message{message}, nil
	}
	var rawMessages []json.RawMessage
	if err := json.Unmarshal(payload, &rawMessages); err != nil {
		return nil, fmt.Errorf("mcp: decode request batch: %w", err)
	}
	if len(rawMessages) == 0 {
		return nil, fmt.Errorf("mcp: request batch is empty")
	}
	if len(rawMessages) > maxBatchMessages {
		return nil, fmt.Errorf("mcp: request batch exceeds %d messages", maxBatchMessages)
	}
	messages := make([]Message, 0, len(rawMessages))
	for index, rawMessage := range rawMessages {
		message, err := decodeMessage(rawMessage)
		if err != nil {
			return nil, fmt.Errorf("mcp: request batch item %d: %w", index, err)
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func decodeMessage(raw json.RawMessage) (Message, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return Message{}, fmt.Errorf("request message must be an object")
	}
	var message Message
	if err := json.Unmarshal(raw, &message); err != nil {
		return Message{}, fmt.Errorf("decode request message: %w", err)
	}
	if message.Method == "" {
		return Message{}, fmt.Errorf("request method is required")
	}
	return message, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("mcp: decode trailing data: %w", err)
	}
	return fmt.Errorf("mcp: multiple JSON values are not allowed")
}
