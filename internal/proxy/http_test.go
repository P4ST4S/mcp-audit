package proxy

import (
	"bytes"
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
