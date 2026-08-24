package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/auth"
	"github.com/P4ST4S/mcp-audit/internal/httpclient"
	"github.com/P4ST4S/mcp-audit/internal/mcp"
	"github.com/P4ST4S/mcp-audit/internal/middleware"
	"github.com/P4ST4S/mcp-audit/internal/policy"
)

func TestHTTPProxyStripsAuthorizationByDefault(t *testing.T) {
	var upstreamHeaders http.Header
	proxy, err := NewHTTPProxy(HTTPConfig{Upstream: "http://upstream.local"})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHeaders = r.Header.Clone()
		return okJSONResponse(), nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`not-json-rpc`)))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if got := upstreamHeaders.Get("Authorization"); got != "" {
		t.Fatalf("authorization = %q, want stripped", got)
	}
}

func TestHTTPProxyForwardsConfiguredAuthorization(t *testing.T) {
	var upstreamHeaders http.Header
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:       "http://upstream.local",
		ForwardHeaders: []string{"Authorization"},
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHeaders = r.Header.Clone()
		return okJSONResponse(), nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`not-json-rpc`)))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if got := upstreamHeaders.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("authorization = %q, want forwarded bearer token", got)
	}
}

func TestHTTPProxyAuthorizationForwardingMigrationScenario(t *testing.T) {
	authRequiredTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(bytes.NewReader([]byte("unauthorized"))),
				Header:     make(http.Header),
			}, nil
		}
		return okJSONResponse(), nil
	})

	strippedProxy, err := NewHTTPProxy(HTTPConfig{Upstream: "http://upstream.local"})
	if err != nil {
		t.Fatalf("new stripped proxy: %v", err)
	}
	strippedProxy.client.Transport = authRequiredTransport
	strippedReq := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`not-json-rpc`)))
	strippedReq.Header.Set("Authorization", "Bearer secret")
	strippedRec := httptest.NewRecorder()

	strippedProxy.ServeHTTP(strippedRec, strippedReq)

	if strippedRec.Code != http.StatusUnauthorized {
		t.Fatalf("stripped status = %d, want 401", strippedRec.Code)
	}
	if got := strippedRec.Body.String(); got != "unauthorized" {
		t.Fatalf("stripped body = %q, want upstream unauthorized body", got)
	}

	forwardingProxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:       "http://upstream.local",
		ForwardHeaders: []string{"Authorization"},
	})
	if err != nil {
		t.Fatalf("new forwarding proxy: %v", err)
	}
	forwardingProxy.client.Transport = authRequiredTransport
	forwardingReq := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`not-json-rpc`)))
	forwardingReq.Header.Set("Authorization", "Bearer secret")
	forwardingRec := httptest.NewRecorder()

	forwardingProxy.ServeHTTP(forwardingRec, forwardingReq)

	if forwardingRec.Code != http.StatusOK {
		t.Fatalf("forwarding status = %d, want 200", forwardingRec.Code)
	}
}

func TestHTTPProxyAuthenticatesStaticBearerPrincipal(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	authenticator, err := auth.NewStaticBearerAuthenticator(token, auth.Principal{
		Subject:  "alice",
		ClientID: "client-1",
		Issuer:   "internal",
		Roles:    []string{"operator"},
	})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	metrics := &httpRejectionMetrics{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:      "http://upstream.local",
		Authenticator: authenticator,
		Metrics:       metrics,
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	upstreamCalls := 0
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamCalls++
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok || principal.Subject != "alice" || principal.ClientID != "client-1" {
			t.Fatalf("upstream principal = %#v, ok = %t", principal, ok)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("upstream Authorization = %q, want stripped", got)
		}
		return okJSONResponse(), nil
	})

	for _, header := range []string{"", "Bearer wrong", "Bearer " + token} {
		req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", strings.NewReader("not-json-rpc"))
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
		if header == "Bearer "+token {
			if rec.Code != http.StatusOK {
				t.Fatalf("valid token status = %d", rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("invalid token status = %d", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="mcp-audit"` {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}
	if len(metrics.rejections) != 2 || metrics.rejections[0] != "authentication" || metrics.rejections[1] != "authentication" {
		t.Fatalf("rejection metrics = %#v", metrics.rejections)
	}
}

func TestHTTPProxyUsesAuthenticatedPrincipalForPolicyAndAudit(t *testing.T) {
	authenticator, err := auth.NewNoneAuthenticator(auth.Principal{
		Subject:  "alice",
		ClientID: "client-1",
		Issuer:   "https://issuer.example.com",
		Roles:    []string{"operator"},
		Scopes:   []string{"tools:delete"},
	})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	engine, err := policy.NewEngine(policy.Config{
		Enabled:       true,
		DefaultAction: policy.ActionAllow,
		Rules: []policy.Rule{{
			Action:  policy.ActionDeny,
			Subject: "alice",
			Issuer:  "https://issuer.example.com",
			Role:    "operator",
			Scope:   "tools:delete",
			Method:  "tools/call",
			Name:    "delete_file",
		}},
	})
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:      "http://upstream.local",
		Authenticator: authenticator,
		Policy:        engine,
		Limiter:       middleware.NewRateLimiter(false, 0),
		Audit:         audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "http"}),
		ServerID:      "filesystem",
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	upstreamCalls := 0
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		upstreamCalls++
		return okJSONResponse(), nil
	})
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file"}}`))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
	if len(store.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(store.entries))
	}
	entry := store.entries[0]
	if entry.ClientID != "client-1" || entry.Principal == nil || entry.Principal.Subject != "alice" || entry.Principal.Issuer != "https://issuer.example.com" {
		t.Fatalf("audit identity = %#v", entry)
	}
	if entry.Error == nil || entry.Error.Code != policyDeniedCode {
		t.Fatalf("audit error = %#v", entry.Error)
	}
}

func TestHTTPProxyDeniesNonToolOperationWhenAllOperationsEnabled(t *testing.T) {
	engine, err := policy.NewEngine(policy.Config{
		Enabled: true,
		Scope:   policy.ScopeAllOperations,
		Rules:   []policy.Rule{{Action: policy.ActionDeny, Method: "prompts/get", Name: "restricted"}},
	})
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Policy:   engine,
		Audit:    audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "http"}),
		Limiter:  middleware.NewRateLimiter(false, 0),
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	upstreamCalls := 0
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		upstreamCalls++
		return okJSONResponse(), nil
	})
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"restricted"}}`))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if upstreamCalls != 0 || len(store.entries) != 1 || store.entries[0].Method != "prompts/get" || store.entries[0].ToolName != "" {
		t.Fatalf("upstream/audit = %d/%#v", upstreamCalls, store.entries)
	}
}

func TestHTTPProxyRejectsOversizedRequestBody(t *testing.T) {
	metrics := &httpRejectionMetrics{}
	upstreamCalls := 0
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:            "http://upstream.local",
		MaxRequestBodyBytes: 4,
		Metrics:             metrics,
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		upstreamCalls++
		return okJSONResponse(), nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", strings.NewReader("12345"))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
	if len(metrics.rejections) != 1 || metrics.rejections[0] != "body_too_large" {
		t.Fatalf("rejection metrics = %#v", metrics.rejections)
	}
}

func TestHTTPProxyAcceptsRequestAtBodyLimit(t *testing.T) {
	proxy, err := NewHTTPProxy(HTTPConfig{Upstream: "http://upstream.local", MaxRequestBodyBytes: 4})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return okJSONResponse(), nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", strings.NewReader("1234"))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestHTTPProxyValidatesBrowserOrigin(t *testing.T) {
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:       "http://upstream.local",
		AllowedOrigins: []string{"https://internal.example.com"},
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return okJSONResponse(), nil
	})

	cases := []struct {
		name   string
		origin string
		status int
	}{
		{name: "non-browser client", status: http.StatusOK},
		{name: "allowed origin", origin: "https://internal.example.com", status: http.StatusOK},
		{name: "allowed default port", origin: "https://internal.example.com:443", status: http.StatusOK},
		{name: "rejected origin", origin: "https://evil.example.com", status: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", strings.NewReader("{}"))
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
		})
	}
}

func TestHTTPProxyValidatesHost(t *testing.T) {
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:     "http://upstream.local",
		AllowedHosts: []string{"localhost", "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return okJSONResponse(), nil
	})

	cases := []struct {
		host   string
		status int
	}{
		{host: "localhost:4422", status: http.StatusOK},
		{host: "127.0.0.1:4422", status: http.StatusOK},
		{host: "attacker.example:4422", status: http.StatusForbidden},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", strings.NewReader("{}"))
		req.Host = tc.host
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("host %q status = %d, want %d", tc.host, rec.Code, tc.status)
		}
	}
}

func TestHTTPProxyForwardsValidMCP2026RequestUnchanged(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"protocolRevision":"2026-07-28"},"requestState":{"round":2},"cache":{"ttl":60}}}`)
	var upstreamBody []byte
	var upstreamHeaders http.Header
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Audit:    testAuditLogger(),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamBody, _ = io.ReadAll(r.Body)
		upstreamHeaders = r.Header.Clone()
		return okJSONResponse(), nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/mcp", bytes.NewReader(body))
	req.Header.Set(mcp.HeaderMethod, "tools/list")
	req.Header.Set(mcp.HeaderProtocolVersion, "2026-07-28")
	req.Header.Set("Mcp-Session-Id", "session-123")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !bytes.Equal(upstreamBody, body) {
		t.Fatalf("upstream body = %s, want %s", upstreamBody, body)
	}
	for header, want := range map[string]string{
		mcp.HeaderMethod:          "tools/list",
		mcp.HeaderProtocolVersion: "2026-07-28",
		"Mcp-Session-Id":          "session-123",
	} {
		if got := upstreamHeaders.Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestHTTPProxyRejectsInconsistentMCPMetadata(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"delete_file"}}`)
	cases := []struct {
		name    string
		headers http.Header
	}{
		{name: "method", headers: http.Header{mcp.HeaderMethod: {"resources/read"}}},
		{name: "name", headers: http.Header{mcp.HeaderName: {"read_file"}}},
		{name: "revision", headers: http.Header{mcp.HeaderProtocolVersion: {"2099-01-01"}}},
		{name: "duplicate", headers: http.Header{mcp.HeaderMethod: {"tools/call", "resources/read"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstreamCalls := 0
			proxy, err := NewHTTPProxy(HTTPConfig{Upstream: "http://upstream.local"})
			if err != nil {
				t.Fatalf("new http proxy: %v", err)
			}
			proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				upstreamCalls++
				return okJSONResponse(), nil
			})
			req := httptest.NewRequest(http.MethodPost, "http://proxy.local/mcp", bytes.NewReader(body))
			req.Header = tc.headers
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if upstreamCalls != 0 {
				t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
			}
			var response struct {
				ID    string          `json:"id"`
				Error *audit.RPCError `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response.ID != "call-1" || response.Error == nil || response.Error.Code != -32600 {
				t.Fatalf("response = %#v", response)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
		})
	}
}

func TestHTTPProxyForwardsProtocolOnlyStreamableGET(t *testing.T) {
	var upstreamMethod string
	var protocolVersion string
	proxy, err := NewHTTPProxy(HTTPConfig{Upstream: "http://upstream.local"})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamMethod = r.Method
		protocolVersion = r.Header.Get(mcp.HeaderProtocolVersion)
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/mcp", nil)
	req.Header.Set(mcp.HeaderProtocolVersion, "2026-07-28")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted || upstreamMethod != http.MethodGet || protocolVersion != "2026-07-28" {
		t.Fatalf("status/method/revision = %d/%q/%q", rec.Code, upstreamMethod, protocolVersion)
	}
}

func TestHTTPProxyStreamsMCP2026SSEUnchanged(t *testing.T) {
	event := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"
	proxy, err := NewHTTPProxy(HTTPConfig{Upstream: "http://upstream.local"})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(event)),
			Header: http.Header{
				"Content-Type":   {"text/event-stream"},
				"Mcp-Session-Id": {"session-123"},
			},
		}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/mcp", nil)
	req.Header.Set(mcp.HeaderProtocolVersion, "2026-07-28")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != event {
		t.Fatalf("status/body = %d/%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Mcp-Session-Id"); got != "session-123" {
		t.Fatalf("Mcp-Session-Id = %q", got)
	}
}

func TestHTTPProxyPreservesLegacyUninspectableTraffic(t *testing.T) {
	upstreamCalls := 0
	proxy, err := NewHTTPProxy(HTTPConfig{Upstream: "http://upstream.local"})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		upstreamCalls++
		return okJSONResponse(), nil
	})
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/mcp", bytes.NewReader([]byte("not-json-rpc")))
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || upstreamCalls != 1 {
		t.Fatalf("status/upstream calls = %d/%d, want 200/1", rec.Code, upstreamCalls)
	}
}

func TestHTTPProxyForwardHeadersAreCaseInsensitive(t *testing.T) {
	var upstreamHeaders http.Header
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:       "http://upstream.local",
		ForwardHeaders: []string{"authorization"},
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHeaders = r.Header.Clone()
		return okJSONResponse(), nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`not-json-rpc`)))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if got := upstreamHeaders.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("authorization = %q, want forwarded bearer token", got)
	}
}

func TestHTTPProxyDoesNotAddConfiguredHeaderWhenAbsent(t *testing.T) {
	var upstreamHeaders http.Header
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:       "http://upstream.local",
		ForwardHeaders: []string{"Authorization"},
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHeaders = r.Header.Clone()
		return okJSONResponse(), nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`not-json-rpc`)))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if _, ok := upstreamHeaders["Authorization"]; ok {
		t.Fatal("authorization header was added even though the client did not send it")
	}
}

func TestHTTPProxyStripsHopByHopRequestHeaders(t *testing.T) {
	var upstreamHeaders http.Header
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:       "http://upstream.local",
		ForwardHeaders: []string{"Authorization"},
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamHeaders = r.Header.Clone()
		return okJSONResponse(), nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`not-json-rpc`)))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Proxy-Authorization", "Basic proxy-secret")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Trailer", "X-Trailer")
	req.Header.Set("Trailers", "X-Trailers")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	for _, header := range []string{"Connection", "Proxy-Authorization", "Transfer-Encoding", "Trailer", "Trailers"} {
		if got := upstreamHeaders.Get(header); got != "" {
			t.Fatalf("%s = %q, want stripped", header, got)
		}
	}
}

func TestHTTPProxyAuditRedactsSensitiveJSONRPCParams(t *testing.T) {
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Audit: audit.NewLogger(audit.LoggerConfig{
			Store:     store,
			Redactor:  middleware.NewRedactor(true, nil),
			Transport: "http",
		}),
		Limiter: middleware.NewRateLimiter(false, 0),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return okJSONResponse(), nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"authorization":"Bearer secret","bearer":"secret","token":"secret"}}}`)))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if len(store.entries) != 1 {
		t.Fatalf("stored entries = %d, want 1", len(store.entries))
	}
	if store.entries[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("outcome = %q, want success", store.entries[0].Outcome)
	}
	if store.entries[0].AuditOperationID == "" {
		t.Fatal("audit_operation_id is empty")
	}
	var params map[string]any
	if err := json.Unmarshal(store.entries[0].Params, &params); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	arguments, ok := params["arguments"].(map[string]any)
	if !ok {
		t.Fatalf("arguments = %#v, want object", params["arguments"])
	}
	for _, key := range []string{"authorization", "bearer", "token"} {
		if got := arguments[key]; got != "[REDACTED]" {
			t.Fatalf("%s = %#v, want [REDACTED]", key, got)
		}
	}
}

// TestHTTPProxyTimesOutUpstreamRequests verifies slow upstream requests use the
// existing bad-gateway error path instead of hanging indefinitely.
func TestHTTPProxyTimesOutUpstreamRequests(t *testing.T) {
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:          "http://upstream.local",
		UpstreamTimeoutMS: 10,
		Audit: audit.NewLogger(audit.LoggerConfig{
			Store:     store,
			Transport: "http",
		}),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = blockingRoundTripper{}

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if len(store.entries) != 1 || store.entries[0].Outcome != audit.OutcomeTimeout {
		t.Fatalf("entries = %#v, want one timeout", store.entries)
	}
}

func TestHTTPProxyAuditsUpstreamConnectionFailure(t *testing.T) {
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Audit:    audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "http"}),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if len(store.entries) != 1 || store.entries[0].Outcome != audit.OutcomeUpstreamError {
		t.Fatalf("entries = %#v, want one upstream_error", store.entries)
	}
}

func TestHTTPProxyDoesNotMarkFailedNotificationSuccessful(t *testing.T) {
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Audit:    audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "http"}),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if len(store.entries) != 1 || store.entries[0].Outcome != audit.OutcomeUpstreamError {
		t.Fatalf("entries = %#v, want one upstream_error", store.entries)
	}
}

func TestHTTPProxyAuditsMalformedUpstreamResponse(t *testing.T) {
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Audit:    audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "http"}),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("not-json")),
			Header:     make(http.Header),
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)))
	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if len(store.entries) != 1 || store.entries[0].Outcome != audit.OutcomeMalformedUpstreamResponse {
		t.Fatalf("entries = %#v, want one malformed_upstream_response", store.entries)
	}
}

func TestHTTPProxyAuditsClientCancellation(t *testing.T) {
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Audit:    audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "http"}),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = blockingRoundTripper{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`))).WithContext(ctx)

	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if len(store.entries) != 1 || store.entries[0].Outcome != audit.OutcomeClientDisconnect {
		t.Fatalf("entries = %#v, want one client_disconnect", store.entries)
	}
}

func TestHTTPProxyAuditsClientWriteFailure(t *testing.T) {
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Audit:    audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "http"}),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return okJSONResponse(), nil
	})
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)))

	proxy.ServeHTTP(newFailingResponseWriter(), req)

	if len(store.entries) != 1 || store.entries[0].Outcome != audit.OutcomeClientDisconnect {
		t.Fatalf("entries = %#v, want one client_disconnect", store.entries)
	}
}

func TestHTTPProxyAuditsIncompleteSSEResponse(t *testing.T) {
	store := &memoryAuditStore{}
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Audit:    audit.NewLogger(audit.LoggerConfig{Store: store, Transport: "http"}),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("data: not-json\n\n")),
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		}, nil
	})
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)))

	proxy.ServeHTTP(httptest.NewRecorder(), req)

	if len(store.entries) != 1 || store.entries[0].Outcome != audit.OutcomeMalformedUpstreamResponse {
		t.Fatalf("entries = %#v, want one malformed_upstream_response", store.entries)
	}
}

func TestHTTPProxyRetriesSafeJSONRPCMethodOnServiceUnavailable(t *testing.T) {
	attempts := 0
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Retry: HTTPRetryConfig{
			MaxRetries:        1,
			InitialIntervalMS: 1,
			MaxIntervalMS:     1,
		},
		Audit: testAuditLogger(),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(bytes.NewReader([]byte("try again"))),
				Header:     http.Header{"Retry-After": []string{"0"}},
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))),
			Header:     make(http.Header),
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestHTTPProxyDoesNotRetryByDefault(t *testing.T) {
	attempts := 0
	proxy, err := NewHTTPProxy(HTTPConfig{Upstream: "http://upstream.local"})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(bytes.NewReader([]byte("try again"))),
			Header:     make(http.Header),
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestHTTPProxyDoesNotRetryToolsCall(t *testing.T) {
	attempts := 0
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Retry: HTTPRetryConfig{
			MaxRetries:        1,
			InitialIntervalMS: 1,
			MaxIntervalMS:     1,
		},
		Limiter: middleware.NewRateLimiter(false, 0),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(bytes.NewReader([]byte("try again"))),
			Header:     make(http.Header),
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file"}}`)))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestHTTPProxyDoesNotRetryConnectionErrorAfterBodyRead(t *testing.T) {
	attempts := 0
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Retry: HTTPRetryConfig{
			MaxRetries:        1,
			InitialIntervalMS: 1,
			MaxIntervalMS:     1,
		},
		Audit: testAuditLogger(),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		_, _ = io.ReadAll(r.Body)
		return nil, fmt.Errorf("connection reset after body read")
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestHTTPProxyRetriesConnectionErrorBeforeBodyRead(t *testing.T) {
	attempts := 0
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		Retry: HTTPRetryConfig{
			MaxRetries:        1,
			InitialIntervalMS: 1,
			MaxIntervalMS:     1,
		},
		Audit: testAuditLogger(),
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, fmt.Errorf("connection refused before body read")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))),
			Header:     make(http.Header),
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestNewHTTPProxyRejectsInvalidTLSCAFile(t *testing.T) {
	_, err := NewHTTPProxy(HTTPConfig{
		Upstream: "https://upstream.local",
		TLS:      httpclient.TLSConfig{CAFile: t.TempDir() + "/missing-ca.pem"},
	})
	if err == nil {
		t.Fatal("expected TLS CA file error")
	}
}

func TestHTTPProxyIncomingTLSHandshake(t *testing.T) {
	certFile, keyFile := writeHTTPServerCertificate(t)
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
		ServerTLS: HTTPServerTLSConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	if proxy.serverTLS == nil || proxy.serverTLS.MinVersion != tls.VersionTLS12 {
		t.Fatalf("server TLS config = %#v, want TLS 1.2 minimum", proxy.serverTLS)
	}

	serverSide, clientSide := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = serverSide.SetDeadline(deadline)
	_ = clientSide.SetDeadline(deadline)
	serverConn := tls.Server(serverSide, proxy.serverTLS.Clone())
	clientConn := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec -- self-signed test certificate
	serverErr := make(chan error, 1)
	go func() { serverErr <- serverConn.Handshake() }()
	if err := clientConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	_ = clientConn.Close()
	_ = serverConn.Close()
}

func TestHTTPProxyRejectsInvalidIncomingTLSConfig(t *testing.T) {
	cases := []HTTPServerTLSConfig{
		{Enabled: true},
		{Enabled: true, CertFile: "server.crt"},
		{CertFile: "server.crt", KeyFile: "server.key"},
		{Enabled: true, CertFile: "missing.crt", KeyFile: "missing.key"},
	}
	for _, config := range cases {
		if _, err := NewHTTPProxy(HTTPConfig{Upstream: "http://upstream.local", ServerTLS: config}); err == nil {
			t.Fatalf("expected error for incoming TLS config %#v", config)
		}
	}
}

func writeHTTPServerCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "server.crt")
	keyFile := filepath.Join(directory, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return certFile, keyFile
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type failingResponseWriter struct {
	header http.Header
}

func newFailingResponseWriter() *failingResponseWriter {
	return &failingResponseWriter{header: make(http.Header)}
}

func (w *failingResponseWriter) Header() http.Header { return w.header }

func (*failingResponseWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("client disconnected")
}

func (*failingResponseWriter) WriteHeader(int) {}

func okJSONResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))),
		Header:     make(http.Header),
	}
}

func testAuditLogger() *audit.Logger {
	return audit.NewLogger(audit.LoggerConfig{Store: &memoryAuditStore{}, Transport: "http"})
}

type blockingRoundTripper struct{}

func (blockingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, fmt.Errorf("round trip canceled: %w", r.Context().Err())
}

// TestNewHTTPProxySetsUpstreamTimeout verifies explicit timeout configuration
// is applied to the upstream HTTP client.
func TestNewHTTPProxySetsUpstreamTimeout(t *testing.T) {
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:          "http://upstream.local",
		UpstreamTimeoutMS: 1500,
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	if proxy.client.Timeout != 1500*time.Millisecond {
		t.Fatalf("client timeout = %s, want 1.5s", proxy.client.Timeout)
	}
}

// TestNewHTTPProxyDefaultsUpstreamTimeout verifies direct proxy construction
// still uses the package default when no timeout is provided.
func TestNewHTTPProxyDefaultsUpstreamTimeout(t *testing.T) {
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream: "http://upstream.local",
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	if proxy.client.Timeout != time.Duration(DefaultHTTPUpstreamTimeoutMS)*time.Millisecond {
		t.Fatalf("client timeout = %s, want %dms", proxy.client.Timeout, DefaultHTTPUpstreamTimeoutMS)
	}
}

func TestHTTPServerUsesConfiguredBindAndHardeningDefaults(t *testing.T) {
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:    "http://upstream.local",
		BindAddress: "127.0.0.1",
		Port:        4422,
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	server := proxy.httpServer()
	if server.Addr != "127.0.0.1:4422" {
		t.Fatalf("server address = %q, want 127.0.0.1:4422", server.Addr)
	}
	if server.MaxHeaderBytes != DefaultHTTPMaxHeaderBytes {
		t.Fatalf("max header bytes = %d", server.MaxHeaderBytes)
	}
	if server.ReadHeaderTimeout != DefaultHTTPReadHeaderTimeout ||
		server.ReadTimeout != DefaultHTTPReadTimeout ||
		server.WriteTimeout != DefaultHTTPWriteTimeout ||
		server.IdleTimeout != DefaultHTTPIdleTimeout {
		t.Fatalf("unexpected server timeouts: %#v", server)
	}
}

func TestNewHTTPProxyRejectsInvalidAccessLists(t *testing.T) {
	cases := []HTTPConfig{
		{Upstream: "http://upstream.local", AllowedOrigins: []string{"file:///tmp"}},
		{Upstream: "http://upstream.local", AllowedOrigins: []string{"https://example.com/path"}},
		{Upstream: "http://upstream.local", AllowedHosts: []string{"https://example.com"}},
	}
	for _, config := range cases {
		if _, err := NewHTTPProxy(config); err == nil {
			t.Fatalf("expected invalid access list error for %#v", config)
		}
	}
}

type httpRejectionMetrics struct {
	rejections []string
}

func (*httpRejectionMetrics) RecordPolicyDecision(string)             {}
func (*httpRejectionMetrics) RecordRateLimitRejection(string, string) {}
func (*httpRejectionMetrics) RecordHTTPUpstreamRetry(string)          {}
func (m *httpRejectionMetrics) RecordHTTPRequestRejection(reason string) {
	m.rejections = append(m.rejections, reason)
}
