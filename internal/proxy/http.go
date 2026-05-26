package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/middleware"
	"github.com/P4ST4S/mcp-audit/internal/policy"
)

// HTTPConfig configures an HTTP MCP proxy.
type HTTPConfig struct {
	Upstream string
	Port     int
	Audit    *audit.Logger
	Limiter  *middleware.RateLimiter
	Policy   *policy.Engine
	Log      *slog.Logger
	ClientID string
	ServerID string
	Metrics  proxyMetrics
}

// HTTPProxy is an HTTP reverse proxy with JSON-RPC auditing.
type HTTPProxy struct {
	config   HTTPConfig
	upstream *url.URL
	client   *http.Client
	log      *slog.Logger
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
	return &HTTPProxy{
		config:   config,
		upstream: upstream,
		client:   &http.Client{},
		log:      logger,
	}, nil
}

// ListenAndServe starts the HTTP proxy server.
func (p *HTTPProxy) ListenAndServe(ctx context.Context) error {
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", p.config.Port),
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errs := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

// ServeHTTP forwards a request to the upstream server and audits JSON-RPC messages.
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startedAt := time.Now()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request", http.StatusBadRequest)
		p.log.Error("failed to read request body", "error", err)
		return
	}
	_ = r.Body.Close()

	pending, reject := p.observeHTTPRequest(body, startedAt)
	if reject != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(reject)
		return
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, p.targetURL(r).String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusBadGateway)
		p.log.Error("failed to create upstream request", "error", err)
		return
	}
	copyHeader(upstreamReq.Header, r.Header)
	if ip := clientIP(r); ip != "" {
		if prior := upstreamReq.Header.Get("X-Forwarded-For"); prior != "" {
			upstreamReq.Header.Set("X-Forwarded-For", prior+", "+ip)
		} else {
			upstreamReq.Header.Set("X-Forwarded-For", ip)
		}
	}
	upstreamReq.Host = p.upstream.Host

	resp, err := p.client.Do(upstreamReq)
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

func (p *HTTPProxy) targetURL(r *http.Request) *url.URL {
	target := *p.upstream
	target.Path = joinURLPath(p.upstream.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery
	return &target
}

func (p *HTTPProxy) observeHTTPRequest(raw []byte, startedAt time.Time) (map[string]pendingCall, []byte) {
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
		toolName := toolNameFromParams(msg.Method, msg.Params)
		call := pendingCall{method: msg.Method, toolName: toolName, params: msg.Params, startedAt: startedAt}
		if msg.Method == "tools/call" {
			decision := p.evaluatePolicy(toolName)
			p.recordPolicyDecision(decision)
			if !decision.Allowed {
				rpcErr := policyError(decision)
				if err := p.record(call, audit.DirectionClientToServer, nil, rpcErr); err != nil {
					p.log.Error("failed to audit policy denied http call", "error", err)
				}
				return pending, buildErrorResponse(msg.ID, rpcErr)
			}
		}
		if msg.Method == "tools/call" && !p.config.Limiter.Allow(p.config.ClientID, toolName) {
			if p.config.Metrics != nil {
				p.config.Metrics.RecordRateLimitRejection(p.config.ClientID, toolName)
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
	return p.config.Audit.Record(audit.Entry{
		Direction:  direction,
		Method:     call.method,
		ToolName:   call.toolName,
		Params:     call.params,
		Result:     result,
		Error:      rpcErr,
		DurationMs: time.Since(call.startedAt).Milliseconds(),
		ClientID:   p.config.ClientID,
		ServerID:   p.config.ServerID,
	})
}

func (p *HTTPProxy) evaluatePolicy(toolName string) policy.Decision {
	if p.config.Policy == nil {
		return policy.Decision{Allowed: true, Action: policy.ActionAllow, RuleIndex: -1}
	}
	return p.config.Policy.Evaluate(policy.Request{
		ClientID: p.config.ClientID,
		ServerID: p.config.ServerID,
		ToolName: toolName,
	})
}

func (p *HTTPProxy) recordPolicyDecision(decision policy.Decision) {
	if p.config.Policy == nil || p.config.Metrics == nil {
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

func hopByHopHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
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
