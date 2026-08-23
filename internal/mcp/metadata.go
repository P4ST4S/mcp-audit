package mcp

import (
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

// InspectRequest validates MCP headers against a single JSON-RPC request body.
func InspectRequest(headers http.Header, body []byte) (RequestMetadata, error) {
	messages, err := DecodeMessages(body)
	if err != nil {
		return RequestMetadata{}, err
	}
	if len(messages) != 1 {
		return RequestMetadata{}, fmt.Errorf("mcp: request metadata headers cannot describe a batch")
	}
	inspectedHeaders, err := inspectHeaders(headers)
	if err != nil {
		return RequestMetadata{}, err
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
