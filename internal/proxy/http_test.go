package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/httpclient"
	"github.com/P4ST4S/mcp-audit/internal/middleware"
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
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

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
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

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
