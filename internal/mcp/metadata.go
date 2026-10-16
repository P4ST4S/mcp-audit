package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RequestKind groups MCP methods into policy-relevant operation families.
type RequestKind string

const (
	RequestKindUnknown    RequestKind = "unknown"
	RequestKindTools      RequestKind = "tools"
	RequestKindResources  RequestKind = "resources"
	RequestKindPrompts    RequestKind = "prompts"
	RequestKindCompletion RequestKind = "completion"
	RequestKindLogging    RequestKind = "logging"
	RequestKindDiscovery  RequestKind = "discovery"
	RequestKindTasks      RequestKind = "tasks"
	RequestKindExtensions RequestKind = "extensions"
)

// RequestMetadata is the normalized, non-mutating view used by gateway controls.
type RequestMetadata struct {
	ProtocolRevision ProtocolRevision
	Method           string
	Name             string
	RequestID        string
	Kind             RequestKind
}

// MetadataFromMessage extracts operation metadata without validating HTTP headers.
func MetadataFromMessage(message Message) RequestMetadata {
	return RequestMetadata{
		Method:    message.Method,
		Name:      nameFromMessage(message),
		RequestID: requestID(message.ID),
		Kind:      classifyMethod(message.Method),
	}
}

// InspectRequest validates MCP headers against a single JSON-RPC request body.
func InspectRequest(headers http.Header, body []byte) (RequestMetadata, error) {
	inspectedHeaders, err := inspectHeaders(headers)
	if err != nil {
		return RequestMetadata{}, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		if inspectedHeaders.method != "" || inspectedHeaders.name != "" {
			return RequestMetadata{}, fmt.Errorf("mcp: method and name headers require a JSON-RPC request body")
		}
		revision, err := protocolRevision(inspectedHeaders.revision, Message{})
		if err != nil {
			return RequestMetadata{}, err
		}
		return RequestMetadata{ProtocolRevision: revision}, nil
	}
	messages, err := DecodeMessages(body)
	if err != nil {
		return RequestMetadata{}, err
	}
	if len(messages) != 1 {
		return RequestMetadata{}, fmt.Errorf("mcp: request metadata headers cannot describe a batch")
	}
	message := messages[0]
	name := nameFromMessage(message)
	if inspectedHeaders.method != "" && inspectedHeaders.method != message.Method {
		return RequestMetadata{}, fmt.Errorf("mcp: method header %q does not match body %q", inspectedHeaders.method, message.Method)
	}
	if inspectedHeaders.name != "" && inspectedHeaders.name != name {
		return RequestMetadata{}, fmt.Errorf("mcp: name header %q does not match body %q", inspectedHeaders.name, name)
	}
	revision, err := protocolRevision(inspectedHeaders.revision, message)
	if err != nil {
		return RequestMetadata{}, err
	}
	return RequestMetadata{
		ProtocolRevision: revision,
		Method:           message.Method,
		Name:             name,
		RequestID:        requestID(message.ID),
		Kind:             classifyMethod(message.Method),
	}, nil
}

func classifyMethod(method string) RequestKind {
	if method == "server/discover" {
		return RequestKindDiscovery
	}
	family, _, _ := strings.Cut(method, "/")
	switch family {
	case "tools":
		return RequestKindTools
	case "resources":
		return RequestKindResources
	case "prompts":
		return RequestKindPrompts
	case "completion":
		return RequestKindCompletion
	case "logging":
		return RequestKindLogging
	case "tasks":
		return RequestKindTasks
	case "extensions":
		return RequestKindExtensions
	default:
		return RequestKindUnknown
	}
}

func nameFromMessage(message Message) string {
	if len(message.Params) == 0 {
		return ""
	}
	var params struct {
		Name     string `json:"name"`
		ToolName string `json:"tool_name"`
		URI      string `json:"uri"`
		TaskID   string `json:"taskId"`
		Ref      struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		} `json:"ref"`
	}
	if json.Unmarshal(message.Params, &params) != nil {
		return ""
	}
	if params.Name != "" {
		return params.Name
	}
	if params.ToolName != "" {
		return params.ToolName
	}
	if params.URI != "" {
		return params.URI
	}
	if params.TaskID != "" {
		return params.TaskID
	}
	if params.Ref.Name != "" {
		return params.Ref.Name
	}
	return params.Ref.URI
}

func requestID(id json.RawMessage) string {
	if len(id) == 0 || string(id) == "null" {
		return ""
	}
	var value string
	if json.Unmarshal(id, &value) == nil {
		return value
	}
	return string(id)
}
