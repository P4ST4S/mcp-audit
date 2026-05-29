package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/httpclient"
	"github.com/P4ST4S/mcp-audit/internal/middleware"
)

// TestHTTPProxyTimesOutUpstreamRequests verifies slow upstream requests use the
// existing bad-gateway error path instead of hanging indefinitely.
func TestHTTPProxyTimesOutUpstreamRequests(t *testing.T) {
	proxy, err := NewHTTPProxy(HTTPConfig{
		Upstream:          "http://upstream.local",
		UpstreamTimeoutMS: 10,
	})
	if err != nil {
		t.Fatalf("new http proxy: %v", err)
	}
	proxy.client.Transport = blockingRoundTripper{}

	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/rpc", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
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
