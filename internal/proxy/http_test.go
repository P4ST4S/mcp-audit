package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
