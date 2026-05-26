package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config configures the Prometheus metrics endpoint and collectors.
type Config struct {
	Enabled               bool
	Port                  int
	Path                  string
	IncludeGoMetrics      bool
	IncludeProcessMetrics bool
	ToolLabels            bool
	Log                   *slog.Logger
}

// Recorder captures operational metrics for the proxy and audit pipeline.
type Recorder interface {
	RecordAuditEntry(entry audit.Entry)
	RecordPolicyDecision(action string)
	RecordRateLimitRejection(clientID, toolName string)
	RecordStorageWrite(backend, mode, status string, duration time.Duration, entries int)
	SetAsyncQueueDepth(depth int)
	SetAsyncQueueCapacity(capacity int)
	RecordAsyncBackpressure()
	RecordAsyncBatch(size int)
}

type noopRecorder struct{}

// Noop returns a metrics recorder that does nothing.
func Noop() Recorder {
	return noopRecorder{}
}

func (noopRecorder) RecordAuditEntry(audit.Entry)                                  {}
func (noopRecorder) RecordPolicyDecision(string)                                   {}
func (noopRecorder) RecordRateLimitRejection(string, string)                       {}
func (noopRecorder) RecordStorageWrite(string, string, string, time.Duration, int) {}
func (noopRecorder) SetAsyncQueueDepth(int)                                        {}
func (noopRecorder) SetAsyncQueueCapacity(int)                                     {}
func (noopRecorder) RecordAsyncBackpressure()                                      {}
func (noopRecorder) RecordAsyncBatch(int)                                          {}

// PrometheusRecorder records metrics into a Prometheus registry.
type PrometheusRecorder struct {
	registry *prometheus.Registry
	config   Config
	log      *slog.Logger

	auditEntries      *prometheus.CounterVec
	policyDecisions   *prometheus.CounterVec
	toolCalls         *prometheus.CounterVec
	rateLimitRejects  *prometheus.CounterVec
	storageWrites     *prometheus.CounterVec
	storageWriteTime  *prometheus.HistogramVec
	asyncBackpressure prometheus.Counter
	asyncBatches      prometheus.Counter
	asyncBatchSize    prometheus.Histogram

	asyncQueueDepth    atomic.Int64
	asyncQueueCapacity atomic.Int64
}

// NewPrometheusRecorder creates a recorder backed by a dedicated Prometheus registry.
func NewPrometheusRecorder(config Config) (*PrometheusRecorder, error) {
	if config.Port <= 0 {
		config.Port = 9091
	}
	if config.Path == "" {
		config.Path = "/metrics"
	}
	logger := config.Log
	if logger == nil {
		logger = slog.Default()
	}
	recorder := &PrometheusRecorder{
		registry: prometheus.NewRegistry(),
		config:   config,
		log:      logger,
		auditEntries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_audit_entries_total",
			Help: "Total audit entries recorded.",
		}, []string{"transport", "direction", "method", "status"}),
		policyDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_audit_policy_decisions_total",
			Help: "Total policy decisions for MCP tools/call requests.",
		}, []string{"action"}),
		toolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_audit_tool_calls_total",
			Help: "Total MCP tools/call audit entries recorded.",
		}, []string{"transport", "tool_name", "status"}),
		rateLimitRejects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_audit_rate_limit_rejections_total",
			Help: "Total tools/call requests rejected by rate limits.",
		}, []string{"client_id", "tool_name"}),
		storageWrites: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_audit_storage_writes_total",
			Help: "Total audit storage writes.",
		}, []string{"backend", "mode", "status"}),
		storageWriteTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "mcp_audit_storage_write_duration_seconds",
			Help:    "Audit storage write duration in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}, []string{"backend", "mode"}),
		asyncBackpressure: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcp_audit_async_backpressure_total",
			Help: "Total times async audit writes encountered a full queue.",
		}),
		asyncBatches: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "mcp_audit_async_batches_total",
			Help: "Total async audit batches written.",
		}),
		asyncBatchSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "mcp_audit_async_batch_size",
			Help:    "Number of audit entries per async storage batch.",
			Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
		}),
	}
	if config.IncludeGoMetrics {
		recorder.registry.MustRegister(collectors.NewGoCollector())
	}
	if config.IncludeProcessMetrics {
		recorder.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}
	recorder.registry.MustRegister(
		recorder.auditEntries,
		recorder.policyDecisions,
		recorder.storageWrites,
		recorder.storageWriteTime,
		recorder.asyncBackpressure,
		recorder.asyncBatches,
		recorder.asyncBatchSize,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "mcp_audit_async_queue_depth",
			Help: "Current number of queued async audit entries.",
		}, func() float64 {
			return float64(recorder.asyncQueueDepth.Load())
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "mcp_audit_async_queue_capacity",
			Help: "Maximum number of queued async audit entries.",
		}, func() float64 {
			return float64(recorder.asyncQueueCapacity.Load())
		}),
	)
	if config.ToolLabels {
		recorder.registry.MustRegister(recorder.toolCalls, recorder.rateLimitRejects)
	}
	return recorder, nil
}

// Handler returns an HTTP handler for Prometheus scraping.
func (r *PrometheusRecorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// ListenAndServe starts the metrics HTTP endpoint.
func (r *PrometheusRecorder) ListenAndServe(ctx context.Context) error {
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", r.config.Port),
		Handler:           http.NewServeMux(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	mux := server.Handler.(*http.ServeMux)
	mux.Handle(r.config.Path, r.Handler())

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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("metrics: shutdown: %w", err)
		}
		return <-errs
	case err := <-errs:
		if err != nil {
			return fmt.Errorf("metrics: listen: %w", err)
		}
		return nil
	}
}

func (r *PrometheusRecorder) RecordAuditEntry(entry audit.Entry) {
	status := "ok"
	if entry.Error != nil {
		status = "rpc_error"
	}
	r.auditEntries.WithLabelValues(entry.Transport, normalizeDirection(entry.Direction), entry.Method, status).Inc()
	if r.config.ToolLabels && entry.Method == "tools/call" {
		toolName := entry.ToolName
		if toolName == "" {
			toolName = "unknown"
		}
		r.toolCalls.WithLabelValues(entry.Transport, toolName, status).Inc()
	}
}

func (r *PrometheusRecorder) RecordPolicyDecision(action string) {
	if action == "" {
		action = "unknown"
	}
	r.policyDecisions.WithLabelValues(action).Inc()
}

func (r *PrometheusRecorder) RecordRateLimitRejection(clientID, toolName string) {
	if !r.config.ToolLabels {
		return
	}
	if clientID == "" {
		clientID = "unknown"
	}
	if toolName == "" {
		toolName = "unknown"
	}
	r.rateLimitRejects.WithLabelValues(clientID, toolName).Inc()
}

func (r *PrometheusRecorder) RecordStorageWrite(backend, mode, status string, duration time.Duration, entries int) {
	if entries <= 0 {
		return
	}
	r.storageWrites.WithLabelValues(backend, mode, status).Add(float64(entries))
	r.storageWriteTime.WithLabelValues(backend, mode).Observe(duration.Seconds())
}

func (r *PrometheusRecorder) SetAsyncQueueDepth(depth int) {
	r.asyncQueueDepth.Store(int64(depth))
}

func (r *PrometheusRecorder) SetAsyncQueueCapacity(capacity int) {
	r.asyncQueueCapacity.Store(int64(capacity))
}

func (r *PrometheusRecorder) RecordAsyncBackpressure() {
	r.asyncBackpressure.Inc()
}

func (r *PrometheusRecorder) RecordAsyncBatch(size int) {
	if size <= 0 {
		return
	}
	r.asyncBatches.Inc()
	r.asyncBatchSize.Observe(float64(size))
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
