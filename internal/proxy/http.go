package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/auth"
	"github.com/P4ST4S/mcp-audit/internal/httpclient"
	"github.com/P4ST4S/mcp-audit/internal/mcp"
	"github.com/P4ST4S/mcp-audit/internal/middleware"
	"github.com/P4ST4S/mcp-audit/internal/policy"
	"github.com/P4ST4S/mcp-audit/internal/retry"
)

// DefaultHTTPUpstreamTimeoutMS is the default timeout for HTTP upstream requests.
const DefaultHTTPUpstreamTimeoutMS = 30000

const (
	DefaultHTTPMaxRequestBodyBytes = int64(10 * 1024 * 1024)
	DefaultHTTPMaxHeaderBytes      = 1024 * 1024
	DefaultHTTPReadHeaderTimeout   = 10 * time.Second
	DefaultHTTPReadTimeout         = 30 * time.Second
	DefaultHTTPWriteTimeout        = 30 * time.Second
	DefaultHTTPIdleTimeout         = 120 * time.Second
)

const (
	defaultHTTPRetryInitialIntervalMS = 200
	defaultHTTPRetryMaxIntervalMS     = 2000
)

// HTTPRetryConfig configures conservative retries to the upstream HTTP MCP server.
type HTTPRetryConfig struct {
	MaxRetries        int
	InitialIntervalMS int
	MaxIntervalMS     int
}

// HTTPServerTLSConfig configures TLS for incoming proxy connections.
type HTTPServerTLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

// HTTPConfig configures an HTTP MCP proxy.
type HTTPConfig struct {
	Upstream    string
	BindAddress string
	Port        int
	// UpstreamTimeoutMS bounds each HTTP request to the upstream MCP server.
	UpstreamTimeoutMS   int
	ForwardHeaders      []string
	MaxRequestBodyBytes int64
	MaxHeaderBytes      int
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	AllowedOrigins      []string
	AllowedHosts        []string
	Authenticator       auth.Authenticator
	ServerTLS           HTTPServerTLSConfig
	TLS                 httpclient.TLSConfig
	Retry               HTTPRetryConfig
	Audit               *audit.Logger
	Limiter             *middleware.RateLimiter
	Policy              *policy.Engine
	Log                 *slog.Logger
	ClientID            string
	ServerID            string
	Metrics             proxyMetrics
}

// HTTPProxy is an HTTP reverse proxy with JSON-RPC auditing.
type HTTPProxy struct {
	config         HTTPConfig
	upstream       *url.URL
	client         *http.Client
	log            *slog.Logger
	forwardHeaders map[string]struct{}
	allowedOrigins map[string]struct{}
	allowedHosts   map[string]struct{}
	serverTLS      *tls.Config
}

// NewHTTPProxy creates an HTTP proxy.
func NewHTTPProxy(config HTTPConfig) (*HTTPProxy, error) {
	if config.Upstream == "" {
		return nil, fmt.Errorf("proxy: http: upstream is required")
	}
	upstream, err := url.Parse(config.Upstream)
	if err != nil {
		return nil, fmt.Errorf("proxy: http: parse upstream: %w", err)
	}
	logger := config.Log
	if logger == nil {
		logger = slog.Default()
	}
	if config.UpstreamTimeoutMS <= 0 {
		config.UpstreamTimeoutMS = DefaultHTTPUpstreamTimeoutMS
	}
	if config.MaxRequestBodyBytes <= 0 {
		config.MaxRequestBodyBytes = DefaultHTTPMaxRequestBodyBytes
	}
	if config.MaxHeaderBytes <= 0 {
		config.MaxHeaderBytes = DefaultHTTPMaxHeaderBytes
	}
	if config.ReadHeaderTimeout <= 0 {
		config.ReadHeaderTimeout = DefaultHTTPReadHeaderTimeout
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = DefaultHTTPReadTimeout
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = DefaultHTTPWriteTimeout
	}
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = DefaultHTTPIdleTimeout
	}
	if config.Retry.MaxRetries < 0 {
		config.Retry.MaxRetries = 0
	}
	if config.Authenticator == nil {
		localClientID := config.ClientID
		if localClientID == "" {
			localClientID = "legacy-local"
		}
		config.Authenticator, err = auth.NewNoneAuthenticator(auth.Principal{
			Subject:  localClientID,
			ClientID: localClientID,
			Issuer:   "static",
		})
		if err != nil {
			return nil, fmt.Errorf("proxy: http: default authenticator: %w", err)
		}
	}
	if config.Retry.InitialIntervalMS <= 0 {
		config.Retry.InitialIntervalMS = defaultHTTPRetryInitialIntervalMS
	}
	if config.Retry.MaxIntervalMS <= 0 {
		config.Retry.MaxIntervalMS = defaultHTTPRetryMaxIntervalMS
	}
	if config.Retry.MaxIntervalMS < config.Retry.InitialIntervalMS {
		config.Retry.MaxIntervalMS = config.Retry.InitialIntervalMS
	}
	client, err := httpclient.New(httpclient.Config{
		Timeout: time.Duration(config.UpstreamTimeoutMS) * time.Millisecond,
		TLS:     config.TLS,
	})
	if err != nil {
		return nil, fmt.Errorf("proxy: http: upstream client: %w", err)
	}
	allowedOrigins, err := normalizedAllowedOrigins(config.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	allowedHosts, err := normalizedAllowedHosts(config.AllowedHosts)
	if err != nil {
		return nil, err
	}
	serverTLS, err := newHTTPServerTLSConfig(config.ServerTLS)
	if err != nil {
		return nil, err
	}
	return &HTTPProxy{
		config:         config,
		upstream:       upstream,
		client:         client,
		log:            logger,
		forwardHeaders: normalizedForwardHeaders(config.ForwardHeaders),
		allowedOrigins: allowedOrigins,
		allowedHosts:   allowedHosts,
		serverTLS:      serverTLS,
	}, nil
}

// ListenAndServe starts the HTTP proxy server.
func (p *HTTPProxy) ListenAndServe(ctx context.Context) error {
	server := p.httpServer()

	errs := make(chan error, 1)
	go func() {
		var err error
		if p.serverTLS == nil {
			err = server.ListenAndServe()
		} else {
			err = server.ListenAndServeTLS("", "")
		}
		if err != nil && err != http.ErrServerClosed {
			errs <- err
			return
		}
		errs <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("proxy: http: shutdown: %w", err)
		}
		return <-errs
	case err := <-errs:
		if err != nil {
			return fmt.Errorf("proxy: http: listen: %w", err)
		}
		return nil
	}
}

func (p *HTTPProxy) httpServer() *http.Server {
	return &http.Server{
		Addr:              net.JoinHostPort(p.config.BindAddress, strconv.Itoa(p.config.Port)),
		Handler:           p,
		MaxHeaderBytes:    p.config.MaxHeaderBytes,
		ReadHeaderTimeout: p.config.ReadHeaderTimeout,
		ReadTimeout:       p.config.ReadTimeout,
		WriteTimeout:      p.config.WriteTimeout,
		IdleTimeout:       p.config.IdleTimeout,
		TLSConfig:         p.serverTLS,
	}
}

func newHTTPServerTLSConfig(config HTTPServerTLSConfig) (*tls.Config, error) {
	if !config.Enabled {
		if config.CertFile != "" || config.KeyFile != "" {
			return nil, fmt.Errorf("proxy: http: incoming TLS certificate requires tls.enabled=true")
		}
		return nil, nil
	}
	if config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("proxy: http: tls.cert_file and tls.key_file are required when TLS is enabled")
	}
	certificate, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("proxy: http: load incoming TLS certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}, nil
}

// ServeHTTP forwards a request to the upstream server and audits JSON-RPC messages.
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.hostAllowed(r.Host) {
		p.rejectHTTPRequest(w, http.StatusForbidden, "host", "host is not allowed")
		return
	}
	if !p.originAllowed(r.Header.Get("Origin")) {
		p.rejectHTTPRequest(w, http.StatusForbidden, "origin", "origin is not allowed")
		return
	}
	principal, err := p.config.Authenticator.Authenticate(r.Context(), r)
	if err != nil {
		p.rejectAuthentication(w)
		return
	}
	if principal == nil {
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		p.log.Error("authenticator returned a nil principal")
		return
	}
	r = r.WithContext(auth.WithPrincipal(r.Context(), principal))
	startedAt := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, p.config.MaxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			p.rejectHTTPRequest(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
			return
		}
		http.Error(w, "failed to read request", http.StatusBadRequest)
		p.log.Error("failed to read request body", "error", err)
		return
	}
	_ = r.Body.Close()
	if err := p.validateMCPRequest(r.Header, body); err != nil {
		p.writeMCPMetadataError(w, body, err)
		return
	}

	pending, reject := p.observeHTTPRequest(body, startedAt, principal)
	if reject != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(reject)
		return
	}

	resp, err := p.doUpstreamRequest(r, body)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		p.log.Error("upstream request failed", "error", err)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	if isEventStream(resp.Header.Get("Content-Type")) {
		w.WriteHeader(resp.StatusCode)
		p.streamSSE(w, resp.Body, pending)
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		p.log.Error("failed to read upstream response", "error", err)
		return
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
	p.observeHTTPResponse(respBody, pending)
}

func (p *HTTPProxy) rejectAuthentication(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-audit"`)
	p.rejectHTTPRequest(w, http.StatusUnauthorized, "authentication", "authentication required")
}

func (p *HTTPProxy) validateMCPRequest(headers http.Header, body []byte) error {
	metadata, err := mcp.InspectRequest(headers, body)
	if err != nil {
		if !hasMCPMetadataHeaders(headers) {
			p.log.Debug("request is not inspectable MCP JSON-RPC", "error", err)
			return nil
		}
		return err
	}
	if metadata.ProtocolRevision == mcp.Protocol20260728 {
		p.log.Debug("inspected MCP 2026 request", "method", metadata.Method, "name", metadata.Name, "request_id", metadata.RequestID)
	}
	return nil
}

func (p *HTTPProxy) writeMCPMetadataError(w http.ResponseWriter, body []byte, cause error) {
	p.log.Warn("rejected inconsistent MCP request metadata", "error", cause)
	id := json.RawMessage("null")
	if messages, err := mcp.DecodeMessages(body); err == nil && len(messages) == 1 && len(messages[0].ID) > 0 {
		id = messages[0].ID
	}
	rpcErr := &audit.RPCError{Code: -32600, Message: "invalid MCP request metadata"}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(buildErrorResponse(id, rpcErr))
}

func hasMCPMetadataHeaders(headers http.Header) bool {
	return len(headers.Values(mcp.HeaderMethod)) > 0 ||
		len(headers.Values(mcp.HeaderName)) > 0 ||
		len(headers.Values(mcp.HeaderProtocolVersion)) > 0
}

func (p *HTTPProxy) doUpstreamRequest(r *http.Request, body []byte) (*http.Response, error) {
	safeToRetry := p.safeToRetry(r.Method, body)
	retryPolicy := p.retryPolicy()
	backoffAttempt := 0
	for attempt := 0; ; attempt++ {
		tracker := &trackingReader{reader: bytes.NewReader(body)}
		upstreamReq, err := p.newUpstreamRequest(r, tracker)
		if err != nil {
			return nil, err
		}
		resp, err := p.client.Do(upstreamReq)
		if !p.shouldRetryUpstream(retryPolicy, attempt, safeToRetry, tracker.bytesRead, resp, err) {
			return resp, err
		}
		if p.config.Metrics != nil {
			p.config.Metrics.RecordHTTPUpstreamRetry(upstreamRetryReason(resp, err))
		}
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
		}
		retryAfter := responseRetryAfter(resp)
		delay := retryPolicy.Delay(backoffAttempt, retryAfter)
		if delay <= 0 {
			delay = retryPolicy.InitialInterval
		}
		if retryAfter <= 0 {
			backoffAttempt++
		}
		p.log.Warn("retrying upstream request", "attempt", attempt+1, "delay_ms", delay.Milliseconds())
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
}

func (p *HTTPProxy) retryPolicy() retry.Policy {
	return retry.Policy{
		MaxRetries:      p.config.Retry.MaxRetries,
		InitialInterval: time.Duration(p.config.Retry.InitialIntervalMS) * time.Millisecond,
		MaxInterval:     time.Duration(p.config.Retry.MaxIntervalMS) * time.Millisecond,
		Multiplier:      2,
		ShouldRetry: retry.StatusCodeClassifier(
			http.StatusTooManyRequests,
			http.StatusServiceUnavailable,
		),
	}
}

func (p *HTTPProxy) newUpstreamRequest(r *http.Request, body io.Reader) (*http.Request, error) {
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, p.targetURL(r).String(), body)
	if err != nil {
		return nil, fmt.Errorf("proxy: http: create upstream request: %w", err)
	}
	p.copyRequestHeader(upstreamReq.Header, r.Header)
	if ip := clientIP(r); ip != "" {
		if prior := upstreamReq.Header.Get("X-Forwarded-For"); prior != "" {
			upstreamReq.Header.Set("X-Forwarded-For", prior+", "+ip)
		} else {
			upstreamReq.Header.Set("X-Forwarded-For", ip)
		}
	}
	upstreamReq.Host = p.upstream.Host
	return upstreamReq, nil
}

func (p *HTTPProxy) shouldRetryUpstream(policy retry.Policy, attempt int, safeToRetry bool, bodyBytesRead int64, resp *http.Response, err error) bool {
	if !safeToRetry {
		return false
	}
	if err != nil && bodyBytesRead != 0 {
		return false
	}
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	return policy.CanRetry(attempt, status, err)
}

func (p *HTTPProxy) safeToRetry(method string, body []byte) bool {
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return true
	}
	if method != http.MethodPost || len(bytes.TrimSpace(body)) == 0 {
		return false
	}
	messages, err := decodeMessages(body)
	if err != nil || len(messages) == 0 {
		return false
	}
	for _, msg := range messages {
		if !safeJSONRPCMethod(msg.Method) {
			return false
		}
	}
	return true
}

func (p *HTTPProxy) targetURL(r *http.Request) *url.URL {
	target := *p.upstream
	target.Path = joinURLPath(p.upstream.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery
	return &target
}

func (p *HTTPProxy) observeHTTPRequest(raw []byte, startedAt time.Time, principal *auth.Principal) (map[string]pendingCall, []byte) {
	pending := make(map[string]pendingCall)
	if len(bytes.TrimSpace(raw)) == 0 {
		return pending, nil
	}
	messages, err := decodeMessages(raw)
	if err != nil {
		p.log.Debug("http request is not JSON-RPC", "error", err)
		return pending, nil
	}
	for _, msg := range messages {
		if msg.Method == "" {
			continue
		}
		metadata := mcp.MetadataFromMessage(mcp.Message{ID: msg.ID, Method: msg.Method, Params: msg.Params})
		toolName := ""
		if msg.Method == "tools/call" {
			toolName = metadata.Name
		}
		call := pendingCall{
			method:    msg.Method,
			requestID: jsonRPCID(msg.ID),
			toolName:  toolName,
			params:    msg.Params,
			startedAt: startedAt,
			principal: auditPrincipal(principal),
		}
		decision := p.evaluatePolicy(principal, metadata.Method, metadata.Name)
		p.recordPolicyDecision(decision)
		if !decision.Allowed {
			rpcErr := policyError(decision)
			if err := p.record(call, audit.DirectionClientToServer, nil, rpcErr); err != nil {
				p.log.Error("failed to audit policy denied http operation", "error", err)
			}
			return pending, buildErrorResponse(msg.ID, rpcErr)
		}
		if msg.Method == "tools/call" && !p.config.Limiter.Allow(principal.ClientID, toolName) {
			if p.config.Metrics != nil {
				p.config.Metrics.RecordRateLimitRejection(principal.ClientID, toolName)
			}
			rpcErr := &audit.RPCError{Code: -32029, Message: "rate limit exceeded"}
			if err := p.record(call, audit.DirectionClientToServer, nil, rpcErr); err != nil {
				p.log.Error("failed to audit rate limited http call", "error", err)
			}
			return pending, buildErrorResponse(msg.ID, rpcErr)
		}
		if len(msg.ID) > 0 {
			pending[string(msg.ID)] = call
			continue
		}
		if err := p.record(call, audit.DirectionClientToServer, nil, nil); err != nil {
			p.log.Error("failed to audit http notification", "error", err)
		}
	}
	return pending, nil
}

func (p *HTTPProxy) observeHTTPResponse(raw []byte, pending map[string]pendingCall) {
	if len(pending) == 0 || len(bytes.TrimSpace(raw)) == 0 {
		return
	}
	messages, err := decodeMessages(raw)
	if err != nil {
		p.log.Warn("failed to inspect http response", "error", err)
		return
	}
	for _, msg := range messages {
		call, ok := pending[string(msg.ID)]
		if !ok {
			continue
		}
		if err := p.record(call, audit.DirectionServerToClient, msg.Result, msg.Error); err != nil {
			p.log.Error("failed to audit http response", "error", err)
		}
		delete(pending, string(msg.ID))
	}
}

func (p *HTTPProxy) streamSSE(w http.ResponseWriter, body io.Reader, pending map[string]pendingCall) {
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(body)
	var data strings.Builder
	for {
		lineBytes, err := reader.ReadBytes('\n')
		if len(lineBytes) > 0 {
			_, _ = w.Write(lineBytes)
		}
		if flusher != nil {
			flusher.Flush()
		}
		if len(lineBytes) == 0 && err != nil {
			if err != io.EOF {
				p.log.Error("failed to stream SSE response", "error", err)
			}
			return
		}
		line := strings.TrimRight(string(lineBytes), "\r\n")
		if strings.HasPrefix(line, "data:") {
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
		if line == "" && data.Len() > 0 {
			p.observeHTTPResponse([]byte(data.String()), pending)
			data.Reset()
		}
		if err != nil {
			if err != io.EOF {
				p.log.Error("failed to stream SSE response", "error", err)
			}
			return
		}
	}
}

func (p *HTTPProxy) record(call pendingCall, direction string, result json.RawMessage, rpcErr *audit.RPCError) error {
	principal := call.principal
	if principal == nil {
		principal = staticAuditPrincipal(p.config.ClientID)
	}
	return p.config.Audit.Record(audit.Entry{
		Direction:  direction,
		Method:     call.method,
		RequestID:  call.requestID,
		ToolName:   call.toolName,
		Params:     call.params,
		Result:     result,
		Error:      rpcErr,
		DurationMs: time.Since(call.startedAt).Milliseconds(),
		ClientID:   principal.ClientID,
		ServerID:   p.config.ServerID,
		Principal:  principal,
	})
}

func (p *HTTPProxy) evaluatePolicy(principal *auth.Principal, method, name string) policy.Decision {
	if p.config.Policy == nil {
		return policy.Decision{Allowed: true, Action: policy.ActionAllow, RuleIndex: -1}
	}
	toolName := ""
	if method == "tools/call" {
		toolName = name
	}
	return p.config.Policy.Evaluate(policy.Request{
		Subject:  principal.Subject,
		ClientID: principal.ClientID,
		Issuer:   principal.Issuer,
		Roles:    principal.Roles,
		Scopes:   principal.Scopes,
		ServerID: p.config.ServerID,
		Method:   method,
		Name:     name,
		ToolName: toolName,
	})
}

func (p *HTTPProxy) recordPolicyDecision(decision policy.Decision) {
	if p.config.Policy == nil || p.config.Metrics == nil || !decision.Applied {
		return
	}
	p.config.Metrics.RecordPolicyDecision(decision.Action)
}

func isEventStream(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.Contains(strings.ToLower(contentType), "text/event-stream")
	}
	return mediaType == "text/event-stream"
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		if hopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func (p *HTTPProxy) copyRequestHeader(dst, src http.Header) {
	for key, values := range src {
		if stripRequestHeader(key, p.forwardHeaders) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func stripRequestHeader(key string, forwardHeaders map[string]struct{}) bool {
	if hopByHopHeader(key) {
		return true
	}
	normalized := strings.ToLower(key)
	if normalized == "authorization" {
		_, ok := forwardHeaders[normalized]
		return !ok
	}
	return false
}

func hopByHopHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "trailers", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func normalizedForwardHeaders(headers []string) map[string]struct{} {
	out := make(map[string]struct{}, len(headers))
	for _, header := range headers {
		header = strings.TrimSpace(strings.ToLower(header))
		if header != "" {
			out[header] = struct{}{}
		}
	}
	return out
}

func normalizedAllowedOrigins(origins []string) (map[string]struct{}, error) {
	normalized := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		value, err := normalizeOrigin(origin)
		if err != nil {
			return nil, fmt.Errorf("proxy: http: allowed origin %q: %w", origin, err)
		}
		normalized[value] = struct{}{}
	}
	return normalized, nil
}

// ValidateHTTPAccessLists validates configured browser origins and Host values.
func ValidateHTTPAccessLists(origins, hosts []string) error {
	if _, err := normalizedAllowedOrigins(origins); err != nil {
		return err
	}
	if _, err := normalizedAllowedHosts(hosts); err != nil {
		return err
	}
	return nil
}

func normalizeOrigin(origin string) (string, error) {
	if origin == "" || strings.TrimSpace(origin) != origin {
		return "", fmt.Errorf("must be a non-empty origin")
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("must contain only scheme and authority")
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", fmt.Errorf("hostname is required")
	}
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	authority := hostname
	if strings.Contains(hostname, ":") {
		authority = "[" + hostname + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(hostname, port)
	}
	return strings.ToLower(parsed.Scheme) + "://" + authority, nil
}

func normalizedAllowedHosts(hosts []string) (map[string]struct{}, error) {
	normalized := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		value, err := normalizeHostname(host)
		if err != nil {
			return nil, fmt.Errorf("proxy: http: allowed host %q: %w", host, err)
		}
		normalized[value] = struct{}{}
	}
	return normalized, nil
}

func normalizeHostname(host string) (string, error) {
	if host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "/?#@") {
		return "", fmt.Errorf("must be a non-empty hostname with optional port")
	}
	hostname := host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		hostname = parsedHost
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		hostname = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	} else if strings.Count(host, ":") == 1 {
		return "", fmt.Errorf("invalid host and port")
	}
	hostname = strings.ToLower(strings.TrimSuffix(strings.Trim(hostname, "[]"), "."))
	if hostname == "" || strings.ContainsFunc(hostname, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return "", fmt.Errorf("invalid hostname")
	}
	return hostname, nil
}

func (p *HTTPProxy) originAllowed(origin string) bool {
	if origin == "" || len(p.allowedOrigins) == 0 {
		return true
	}
	normalized, err := normalizeOrigin(origin)
	if err != nil {
		return false
	}
	_, ok := p.allowedOrigins[normalized]
	return ok
}

func (p *HTTPProxy) hostAllowed(host string) bool {
	if len(p.allowedHosts) == 0 {
		return true
	}
	normalized, err := normalizeHostname(host)
	if err != nil {
		return false
	}
	_, ok := p.allowedHosts[normalized]
	return ok
}

func (p *HTTPProxy) rejectHTTPRequest(w http.ResponseWriter, status int, reason, message string) {
	if recorder, ok := p.config.Metrics.(interface{ RecordHTTPRequestRejection(string) }); ok {
		recorder.RecordHTTPRequestRejection(reason)
	}
	http.Error(w, message, status)
}

func joinURLPath(basePath, requestPath string) string {
	if basePath == "" || basePath == "/" {
		return requestPath
	}
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(requestPath, "/")
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type trackingReader struct {
	reader    *bytes.Reader
	bytesRead int64
}

func (r *trackingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytesRead += int64(n)
	return n, err
}

func safeJSONRPCMethod(method string) bool {
	switch method {
	case "initialize",
		"ping",
		"tools/list",
		"resources/list",
		"resources/read",
		"resources/templates/list",
		"prompts/list",
		"prompts/get",
		"completion/complete":
		return true
	default:
		return false
	}
}

func responseRetryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	return retry.ParseRetryAfter(resp.Header.Get("Retry-After"))
}

func upstreamRetryReason(resp *http.Response, err error) string {
	if err != nil {
		return "network"
	}
	if resp == nil {
		return "unknown"
	}
	return strconv.Itoa(resp.StatusCode)
}
