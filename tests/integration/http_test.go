//go:build integration

package integration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/golang-jwt/jwt/v5"
)

const staticBearerToken = "abcdef0123456789abcdef0123456789"

func TestHTTPBinarySecurityGatewayFlow(t *testing.T) {
	var upstreamCalls atomic.Int32
	var forwardedRevision atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		forwardedRevision.Store(request.Header.Get("Mcp-Protocol-Version"))
		body, _ := io.ReadAll(request.Body)
		var envelope struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &envelope)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, envelope.ID)
	}))
	defer upstream.Close()

	directory := t.TempDir()
	auditPath := filepath.Join(directory, "audit.jsonl")
	port := freePort(t)
	config := fmt.Sprintf(`proxy:
  transport: http
  upstream: %q
  bind_address: 127.0.0.1
  port: %d
  client_id: legacy-client
  server_id: integration-upstream
  http:
    max_request_body_bytes: 512
auth:
  mode: static_bearer
  static:
    subject: alice
    client_id: authenticated-client
    issuer: integration
    roles: [operator]
    scopes: [mcp:read]
audit:
  storage: jsonl
  path: %q
  sign: true
policy:
  enabled: true
  default_action: allow
  scope: all_operations
  rules:
    - action: deny
      role: operator
      method: resources/read
      name: file:///secret
dashboard:
  enabled: false
metrics:
  enabled: false
`, upstream.URL, port, auditPath)
	command, stderr := startHTTPProxy(t, writeConfig(t, config), port, map[string]string{
		"MCP_AUDIT_STATIC_BEARER_TOKEN": staticBearerToken,
	})
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/mcp", port)

	unauthorized := postMCP(t, http.DefaultClient, baseURL, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.StatusCode)
	}
	_ = unauthorized.Body.Close()

	inconsistent := postMCP(t, http.DefaultClient, baseURL, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, map[string]string{
		"Authorization":        "Bearer " + staticBearerToken,
		"Mcp-Method":           "resources/read",
		"Mcp-Protocol-Version": "2026-07-28",
	})
	if inconsistent.StatusCode != http.StatusBadRequest {
		t.Fatalf("inconsistent metadata status = %d", inconsistent.StatusCode)
	}
	_ = inconsistent.Body.Close()

	denied := postMCP(t, http.DefaultClient, baseURL, `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///secret"}}`, map[string]string{
		"Authorization": "Bearer " + staticBearerToken,
	})
	var deniedBody struct {
		Error *audit.RPCError `json:"error"`
	}
	decodeHTTPJSON(t, denied, &deniedBody)
	if deniedBody.Error == nil || deniedBody.Error.Code != -32030 {
		t.Fatalf("policy response = %#v", deniedBody)
	}

	accepted := postMCP(t, http.DefaultClient, baseURL, `{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"protocolRevision":"2026-07-28"}}}`, map[string]string{
		"Authorization":        "Bearer " + staticBearerToken,
		"Mcp-Method":           "tools/list",
		"Mcp-Protocol-Version": "2026-07-28",
	})
	var acceptedBody struct {
		Result map[string]any `json:"result"`
	}
	decodeHTTPJSON(t, accepted, &acceptedBody)
	if acceptedBody.Result["ok"] != true || forwardedRevision.Load() != "2026-07-28" {
		t.Fatalf("accepted response/revision = %#v/%v", acceptedBody, forwardedRevision.Load())
	}

	oversized := postMCP(t, http.DefaultClient, baseURL, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"payload":"`+strings.Repeat("x", 600)+`"}}}`, map[string]string{
		"Authorization": "Bearer " + staticBearerToken,
	})
	if oversized.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", oversized.StatusCode)
	}
	_ = oversized.Body.Close()

	stopProcess(t, command, stderr)
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls.Load())
	}
	entries := readAuditEntries(t, auditPath)
	if len(entries) != 2 {
		t.Fatalf("audit entries = %#v, want deny and success", entries)
	}
	if entries[0].Outcome != audit.OutcomeDenied || entries[0].Principal == nil || entries[0].Principal.Subject != "alice" {
		t.Fatalf("denied principal audit = %#v", entries[0])
	}
	if entries[1].Outcome != audit.OutcomeSuccess || entries[1].Integrity == nil {
		t.Fatalf("accepted audit = %#v", entries[1])
	}
}

func TestHTTPBinaryIncomingTLS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()
	certFile, keyFile := writeServerCertificate(t)
	port := freePort(t)
	config := fmt.Sprintf(`proxy:
  transport: http
  upstream: %q
  bind_address: 127.0.0.1
  port: %d
  tls:
    enabled: true
    cert_file: %q
    key_file: %q
audit:
  path: %q
  sign: true
dashboard:
  enabled: false
metrics:
  enabled: false
`, upstream.URL, port, certFile, keyFile, filepath.Join(t.TempDir(), "audit.jsonl"))
	command, stderr := startHTTPProxy(t, writeConfig(t, config), port, nil)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}} //nolint:gosec -- test certificate
	response := postMCP(t, client, fmt.Sprintf("https://127.0.0.1:%d/mcp", port), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
	if response.StatusCode != http.StatusOK || response.TLS == nil || response.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("TLS status/state = %d/%#v", response.StatusCode, response.TLS)
	}
	_ = response.Body.Close()
	stopProcess(t, command, stderr)
}

func TestHTTPBinaryOIDCPrincipalReachesPolicy(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	const keyID = "integration-key"
	var issuerURL string
	identityProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": keyID,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			}},
		})
	}))
	defer identityProvider.Close()
	issuerURL = identityProvider.URL

	upstreamCalls := atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer upstream.Close()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	port := freePort(t)
	config := fmt.Sprintf(`proxy:
  transport: http
  upstream: %q
  bind_address: 127.0.0.1
  port: %d
  server_id: integration-upstream
auth:
  mode: oidc
  oidc:
    issuer: %q
    audience: mcp-audit
    jwks_uri: %q
    allowed_methods: [RS256]
    client_id_claim: client_id
    roles_claim: roles
    scopes_claim: scope
audit:
  path: %q
  sign: true
policy:
  enabled: true
  default_action: allow
  scope: all_operations
  rules:
    - action: deny
      role: auditor
      method: resources/read
      name: file:///secret
dashboard:
  enabled: false
metrics:
  enabled: false
`, upstream.URL, port, issuerURL, issuerURL, auditPath)
	command, stderr := startHTTPProxy(t, writeConfig(t, config), port, nil)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/mcp", port)

	invalidToken := signJWT(t, privateKey, keyID, issuerURL, "wrong-audience")
	invalid := postMCP(t, http.DefaultClient, baseURL, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{
		"Authorization": "Bearer " + invalidToken,
	})
	if invalid.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid audience status = %d", invalid.StatusCode)
	}
	_ = invalid.Body.Close()

	validToken := signJWT(t, privateKey, keyID, issuerURL, "mcp-audit")
	denied := postMCP(t, http.DefaultClient, baseURL, `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///secret"}}`, map[string]string{
		"Authorization": "Bearer " + validToken,
	})
	var deniedBody struct {
		Error *audit.RPCError `json:"error"`
	}
	decodeHTTPJSON(t, denied, &deniedBody)
	if deniedBody.Error == nil || deniedBody.Error.Code != -32030 {
		t.Fatalf("OIDC policy response = %#v", deniedBody)
	}

	stopProcess(t, command, stderr)
	if upstreamCalls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls.Load())
	}
	entries := readAuditEntries(t, auditPath)
	if len(entries) != 1 || entries[0].Principal == nil || entries[0].Principal.Subject != "bob" || entries[0].Principal.ClientID != "oidc-client" || entries[0].Principal.Issuer != issuerURL {
		t.Fatalf("OIDC principal audit = %#v", entries)
	}
}

func signJWT(t *testing.T, privateKey *rsa.PrivateKey, keyID, issuer, audience string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":       issuer,
		"aud":       audience,
		"sub":       "bob",
		"client_id": "oidc-client",
		"roles":     []string{"auditor"},
		"scope":     "mcp:read",
		"iat":       now.Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	})
	token.Header["kid"] = keyID
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

func startHTTPProxy(t *testing.T, configPath string, port int, env map[string]string) (*exec.Cmd, *lockedBuffer) {
	t.Helper()
	if env == nil {
		env = make(map[string]string)
	}
	env["MCP_AUDIT_SIGNING_SECRET"] = signingSecret
	command := exec.Command(binaryPath, "--config", configPath, "--log-level", "error")
	command.Env = commandEnv(env, "AUDIT_SECRET")
	stderr := newLockedBuffer()
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start HTTP proxy: %v", err)
	}
	t.Cleanup(func() {
		if command.Process != nil && command.ProcessState == nil {
			_ = command.Process.Kill()
		}
	})
	waitForPort(t, port, command, stderr)
	return command, stderr
}

func postMCP(t *testing.T, client *http.Client, url, body string, headers map[string]string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	return response
}

func decodeHTTPJSON(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatalf("decode HTTP JSON: %v", err)
	}
}

func writeServerCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  nil,
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
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}
