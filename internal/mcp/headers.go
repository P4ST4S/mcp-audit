package mcp

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
	HeaderProtocolVersion = "Mcp-Protocol-Version"
)

type requestHeaders struct {
	method   string
	name     string
	revision string
}

func inspectHeaders(headers http.Header) (requestHeaders, error) {
	method, err := singleHeader(headers, HeaderMethod)
	if err != nil {
		return requestHeaders{}, err
	}
	name, err := singleHeader(headers, HeaderName)
	if err != nil {
		return requestHeaders{}, err
	}
	revision, err := singleHeader(headers, HeaderProtocolVersion)
	if err != nil {
		return requestHeaders{}, err
	}
	return requestHeaders{method: method, name: name, revision: revision}, nil
}

func singleHeader(headers http.Header, name string) (string, error) {
	values := headers.Values(name)
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("mcp: header %s must occur at most once", name)
	}
	value := strings.TrimSpace(values[0])
	if value == "" || value != values[0] {
		return "", fmt.Errorf("mcp: header %s must be non-empty without surrounding whitespace", name)
	}
	return value, nil
}
