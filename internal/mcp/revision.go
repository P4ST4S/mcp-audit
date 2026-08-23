package mcp

import (
	"encoding/json"
	"fmt"
)

// ProtocolRevision identifies an MCP protocol revision understood by the proxy.
type ProtocolRevision string

const (
	ProtocolLegacy20251125 ProtocolRevision = "2025-11-25"
	Protocol20260728       ProtocolRevision = "2026-07-28"
)

func protocolRevision(headerRevision string, message Message) (ProtocolRevision, error) {
	bodyRevision := revisionFromMessage(message)
	if headerRevision != "" {
		revision := ProtocolRevision(headerRevision)
		if !revision.Supported() {
			return "", fmt.Errorf("mcp: unsupported protocol revision %q", headerRevision)
		}
		if bodyRevision != "" && bodyRevision != revision {
			return "", fmt.Errorf("mcp: protocol revision header %q does not match body %q", revision, bodyRevision)
		}
		return revision, nil
	}
	if bodyRevision != "" {
		if !bodyRevision.Supported() {
			return "", fmt.Errorf("mcp: unsupported protocol revision %q", bodyRevision)
		}
		return bodyRevision, nil
	}
	if message.Method == "server/discover" {
		return Protocol20260728, nil
	}
	return ProtocolLegacy20251125, nil
}

// Supported reports whether the revision has explicit gateway inspection rules.
func (r ProtocolRevision) Supported() bool {
	return r == ProtocolLegacy20251125 || r == Protocol20260728
}

func revisionFromMessage(message Message) ProtocolRevision {
	if len(message.Params) == 0 {
		return ""
	}
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
		Meta            struct {
			ProtocolVersion  string `json:"protocolVersion"`
			ProtocolRevision string `json:"protocolRevision"`
		} `json:"_meta"`
	}
	if json.Unmarshal(message.Params, &params) != nil {
		return ""
	}
	if params.ProtocolVersion != "" {
		return ProtocolRevision(params.ProtocolVersion)
	}
	if params.Meta.ProtocolRevision != "" {
		return ProtocolRevision(params.Meta.ProtocolRevision)
	}
	return ProtocolRevision(params.Meta.ProtocolVersion)
}
