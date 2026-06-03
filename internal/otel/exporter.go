package otel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/httpclient"
	"github.com/P4ST4S/mcp-audit/internal/retry"
)

const (
	defaultEndpoint        = "http://localhost:4318"
	defaultServiceName     = "mcp-audit"
	defaultQueueSize       = 1024
	defaultBatchSize       = 64
	defaultFlushIntervalMS = 1000
	defaultTimeoutMS       = 5000
	defaultRetryInitialMS  = 200
	defaultRetryMaxMS      = 2000

	spanKindInternal = 1
	statusCodeOK     = 1
	statusCodeError  = 2
)

// MetricsRecorder records OTLP exporter metrics.
type MetricsRecorder interface {
	RecordOTelExport(status string, duration time.Duration, spans int)
	RecordOTelDrop(reason string, spans int)
	SetOTelQueueDepth(depth int)
	SetOTelQueueCapacity(capacity int)
}

// Config configures direct OTLP/HTTP JSON trace export.
type Config struct {
	Enabled               bool
	Endpoint              string
	ServiceName           string
	Storage               string
	Upstream              string
	Headers               map[string]string
	TLSCAFile             string
	TLSServerName         string
	TLSInsecureSkipVerify bool
	QueueSize             int
	BatchSize             int
	FlushIntervalMS       int
	TimeoutMS             int
	MaxRetries            int
	RetryInitialMS        int
	RetryMaxMS            int
	Metrics               MetricsRecorder
	Log                   *slog.Logger
}

// Exporter exports audit entries as OTLP/HTTP JSON spans.
type Exporter struct {
	config        Config
	client        *http.Client
	endpoint      string
	serverAddress string
	serverPort    int
	headers       map[string]string
	metrics       MetricsRecorder
	log           *slog.Logger

	entries chan audit.Entry
	closed  atomic.Bool
	once    sync.Once
	closeMu sync.RWMutex
	wg      sync.WaitGroup
}

// NewExporter creates and starts an OTLP exporter.
func NewExporter(config Config) (*Exporter, error) {
	if config.Endpoint == "" {
		config.Endpoint = defaultEndpoint
	}
	if config.ServiceName == "" {
		config.ServiceName = defaultServiceName
	}
	if config.QueueSize <= 0 {
		config.QueueSize = defaultQueueSize
	}
	if config.BatchSize <= 0 {
		config.BatchSize = defaultBatchSize
	}
	if config.FlushIntervalMS <= 0 {
		config.FlushIntervalMS = defaultFlushIntervalMS
	}
	if config.TimeoutMS <= 0 {
		config.TimeoutMS = defaultTimeoutMS
	}
	if config.MaxRetries < 0 {
		config.MaxRetries = 0
	}
	if config.RetryInitialMS <= 0 {
		config.RetryInitialMS = defaultRetryInitialMS
	}
	if config.RetryMaxMS <= 0 {
		config.RetryMaxMS = defaultRetryMaxMS
	}
	if config.RetryMaxMS < config.RetryInitialMS {
		config.RetryMaxMS = config.RetryInitialMS
	}
	endpoint, err := tracesEndpoint(config.Endpoint)
	if err != nil {
		return nil, err
	}
	client, err := newHTTPClient(config)
	if err != nil {
		return nil, err
	}
	logger := config.Log
	if logger == nil {
		logger = slog.Default()
	}
	serverAddress, serverPort := upstreamAddress(config.Upstream)
	exporter := &Exporter{
		config:        config,
		client:        client,
		endpoint:      endpoint,
		serverAddress: serverAddress,
		serverPort:    serverPort,
		headers:       copyHeaders(config.Headers),
		metrics:       config.Metrics,
		log:           logger,
		entries:       make(chan audit.Entry, config.QueueSize),
	}
	exporter.updateQueueMetrics()
	if exporter.metrics != nil {
		exporter.metrics.SetOTelQueueCapacity(cap(exporter.entries))
	}
	exporter.wg.Add(1)
	go exporter.run()
	return exporter, nil
}

// ExportAuditEntry queues one audit entry for OTLP export.
func (e *Exporter) ExportAuditEntry(entry audit.Entry) error {
	if e == nil || entry.Method != "tools/call" {
		return nil
	}
	e.closeMu.RLock()
	defer e.closeMu.RUnlock()
	if e.closed.Load() {
		return fmt.Errorf("otel: exporter is closed")
	}
	select {
	case e.entries <- entry:
		e.updateQueueMetrics()
		return nil
	default:
		if e.metrics != nil {
			e.metrics.RecordOTelDrop("queue_full", 1)
		}
		return fmt.Errorf("otel: export queue is full")
	}
}

// Close flushes queued spans and stops the exporter.
func (e *Exporter) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.once.Do(func() {
		e.closeMu.Lock()
		defer e.closeMu.Unlock()
		e.closed.Store(true)
		close(e.entries)
	})
	wait := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(wait)
	}()
	select {
	case <-wait:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("otel: close: %w", ctx.Err())
	}
}

func (e *Exporter) run() {
	defer e.wg.Done()
	ticker := time.NewTicker(time.Duration(e.config.FlushIntervalMS) * time.Millisecond)
	defer ticker.Stop()
	batch := make([]audit.Entry, 0, e.config.BatchSize)
	for {
		select {
		case entry, ok := <-e.entries:
			e.updateQueueMetrics()
			if !ok {
				e.flush(batch)
				return
			}
			batch = append(batch, entry)
			if len(batch) >= e.config.BatchSize {
				e.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) == 0 {
				continue
			}
			e.flush(batch)
			batch = batch[:0]
		}
	}
}

func (e *Exporter) flush(entries []audit.Entry) {
	if len(entries) == 0 {
		return
	}
	payload, err := e.requestBody(entries)
	if err != nil {
		e.log.Warn("failed to build otlp payload", "error", err)
		if e.metrics != nil {
			e.metrics.RecordOTelDrop("encode_error", len(entries))
		}
		return
	}
	e.exportPayload(payload, len(entries))
	e.updateQueueMetrics()
}

func (e *Exporter) exportPayload(payload []byte, spans int) {
	retryPolicy := e.retryPolicy()
	attempts := e.config.MaxRetries + 1
	backoffAttempt := 0
	for attempt := 0; attempt < attempts; attempt++ {
		startedAt := time.Now()
		status, retryAfter, body, err := e.postPayload(payload)
		duration := time.Since(startedAt)
		if err == nil && status >= http.StatusOK && status < http.StatusMultipleChoices {
			if e.metrics != nil {
				e.metrics.RecordOTelExport("ok", duration, spans)
			}
			return
		}
		retryable := retryPolicy.IsRetryable(status, err)
		finalAttempt := attempt == attempts-1
		if !retryable || finalAttempt {
			statusLabel := "error"
			if !retryable {
				statusLabel = "permanent_error"
			}
			if e.metrics != nil {
				e.metrics.RecordOTelExport(statusLabel, duration, spans)
				e.metrics.RecordOTelDrop(statusLabel, spans)
			}
			if err != nil {
				e.log.Warn("failed to export otlp traces", "error", err, "attempt", attempt+1)
				return
			}
			e.log.Warn("otlp export rejected", "status", status, "body", body, "attempt", attempt+1)
			return
		}
		if e.metrics != nil {
			e.metrics.RecordOTelExport("retry", duration, spans)
		}
		delay := retryPolicy.Delay(backoffAttempt, retryAfter)
		if retryAfter <= 0 {
			backoffAttempt++
		}
		time.Sleep(delay)
	}
}

func (e *Exporter) retryPolicy() retry.Policy {
	return retry.Policy{
		MaxRetries:      e.config.MaxRetries,
		InitialInterval: time.Duration(e.config.RetryInitialMS) * time.Millisecond,
		MaxInterval:     time.Duration(e.config.RetryMaxMS) * time.Millisecond,
		Multiplier:      2,
		ShouldRetry:     retry.ShouldRetry,
	}
}

func (e *Exporter) postPayload(payload []byte) (int, time.Duration, string, error) {
	req, err := http.NewRequest(http.MethodPost, e.endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, 0, "", err
	}
	for key, value := range e.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/json")
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "mcp-audit-otlp/1")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return resp.StatusCode, 0, "", nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return resp.StatusCode, retry.ParseRetryAfter(resp.Header.Get("Retry-After")), string(body), nil
}

func (e *Exporter) requestBody(entries []audit.Entry) ([]byte, error) {
	spans := make([]otlpSpan, 0, len(entries))
	for _, entry := range entries {
		span, err := e.spanFromEntry(entry)
		if err != nil {
			return nil, err
		}
		spans = append(spans, span)
	}
	payload := tracesPayload{
		ResourceSpans: []resourceSpans{
			{
				Resource: resource{
					Attributes: []keyValue{
						stringAttr(attrServiceName, e.config.ServiceName),
					},
				},
				ScopeSpans: []scopeSpans{
					{
						Scope: instrumentationScope{
							Name: "github.com/P4ST4S/mcp-audit/internal/otel",
						},
						Spans: spans,
					},
				},
			},
		},
	}
	return json.Marshal(payload)
}

func (e *Exporter) spanFromEntry(entry audit.Entry) (otlpSpan, error) {
	traceID, err := randomHex(16)
	if err != nil {
		return otlpSpan{}, err
	}
	spanID, err := randomHex(8)
	if err != nil {
		return otlpSpan{}, err
	}
	end := entry.Timestamp
	if end.IsZero() {
		end = time.Now().UTC()
	}
	start := end.Add(-time.Duration(entry.DurationMs) * time.Millisecond)
	if entry.DurationMs < 0 {
		start = end
	}
	span := otlpSpan{
		TraceID:           traceID,
		SpanID:            spanID,
		Name:              spanName(entry),
		Kind:              spanKindInternal,
		StartTimeUnixNano: strconv.FormatInt(start.UnixNano(), 10),
		EndTimeUnixNano:   strconv.FormatInt(end.UnixNano(), 10),
		Attributes:        e.attributes(entry),
		Status:            otlpStatus{Code: statusCodeOK},
	}
	if entry.Error != nil {
		span.Status = otlpStatus{Code: statusCodeError, Message: entry.Error.Message}
	} else if toolResultIsError(entry.Result) {
		span.Status = otlpStatus{Code: statusCodeError, Message: "tool_error"}
	}
	return span, nil
}

func (e *Exporter) attributes(entry audit.Entry) []keyValue {
	attrs := []keyValue{
		stringAttr(attrMCPMethodName, entry.Method),
		stringAttr(attrNetworkTransport, networkTransport(entry.Transport)),
		stringAttr(attrMCPAuditEntryID, entry.ID),
		stringAttr(attrMCPAuditDirection, normalizeDirection(entry.Direction)),
		boolAttr(attrMCPAuditSignaturePresent, entry.Signature != ""),
	}
	if entry.Transport == "http" {
		attrs = append(attrs, stringAttr(attrNetworkProtocolName, "http"))
	}
	if entry.Method == "tools/call" {
		attrs = append(attrs, stringAttr(attrGenAIOperationName, "execute_tool"))
	}
	if entry.RequestID != "" {
		attrs = append(attrs, stringAttr(attrJSONRPCRequestID, entry.RequestID))
	}
	if entry.ToolName != "" {
		attrs = append(attrs, stringAttr(attrGenAIToolName, entry.ToolName))
	}
	if entry.ClientID != "" {
		attrs = append(attrs, stringAttr(attrMCPAuditClientID, entry.ClientID))
	}
	if entry.ServerID != "" {
		attrs = append(attrs, stringAttr(attrMCPAuditServerID, entry.ServerID))
	}
	if e.config.Storage != "" {
		attrs = append(attrs, stringAttr(attrMCPAuditStorage, e.config.Storage))
	}
	if e.serverAddress != "" {
		attrs = append(attrs, stringAttr(attrServerAddress, e.serverAddress))
	}
	if e.serverPort > 0 {
		attrs = append(attrs, intAttr(attrServerPort, int64(e.serverPort)))
	}
	if entry.Error != nil {
		attrs = append(attrs,
			intAttr(attrRPCResponseStatusCode, int64(entry.Error.Code)),
			stringAttr(attrErrorType, errorType(entry.Error.Code)),
		)
	} else if toolResultIsError(entry.Result) {
		attrs = append(attrs, stringAttr(attrErrorType, "tool_error"))
	}
	return attrs
}

func tracesEndpoint(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("otel: parse endpoint: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("otel: endpoint must include scheme and host")
	}
	if strings.HasSuffix(parsed.Path, "/v1/traces") {
		return parsed.String(), nil
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/v1/traces"
	return parsed.String(), nil
}

func newHTTPClient(config Config) (*http.Client, error) {
	client, err := httpclient.New(httpclient.Config{
		Timeout: time.Duration(config.TimeoutMS) * time.Millisecond,
		TLS: httpclient.TLSConfig{
			CAFile:             config.TLSCAFile,
			ServerName:         config.TLSServerName,
			InsecureSkipVerify: config.TLSInsecureSkipVerify,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("otel: %w", err)
	}
	return client, nil
}

func upstreamAddress(upstream string) (string, int) {
	parsed, err := url.Parse(upstream)
	if err != nil || parsed.Host == "" {
		return "", 0
	}
	host := parsed.Hostname()
	port := 0
	if rawPort := parsed.Port(); rawPort != "" {
		if parsedPort, err := strconv.Atoi(rawPort); err == nil {
			port = parsedPort
		}
	} else {
		switch parsed.Scheme {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), port
	}
	return host, port
}

func copyHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func (e *Exporter) updateQueueMetrics() {
	if e.metrics == nil {
		return
	}
	e.metrics.SetOTelQueueDepth(len(e.entries))
}

func spanName(entry audit.Entry) string {
	if entry.ToolName == "" {
		return entry.Method
	}
	return entry.Method + " " + entry.ToolName
}

func networkTransport(transport string) string {
	switch transport {
	case "stdio":
		return "pipe"
	case "http":
		return "tcp"
	default:
		return transport
	}
}

func normalizeDirection(direction string) string {
	switch direction {
	case audit.DirectionClientToServer:
		return "client_to_server"
	case audit.DirectionServerToClient:
		return "server_to_client"
	default:
		if direction == "" {
			return "unknown"
		}
		return direction
	}
}

func errorType(code int) string {
	switch code {
	case -32029:
		return "rate_limited"
	case -32030:
		return "policy_denied"
	default:
		return "jsonrpc_error"
	}
}

func toolResultIsError(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var result struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return false
	}
	return result.IsError
}

func randomHex(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("otel: random id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
