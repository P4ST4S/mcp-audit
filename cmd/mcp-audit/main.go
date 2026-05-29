package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/audit/storage"
	"github.com/P4ST4S/mcp-audit/internal/dashboard"
	"github.com/P4ST4S/mcp-audit/internal/metrics"
	"github.com/P4ST4S/mcp-audit/internal/middleware"
	"github.com/P4ST4S/mcp-audit/internal/otel"
	"github.com/P4ST4S/mcp-audit/internal/policy"
	"github.com/P4ST4S/mcp-audit/internal/proxy"
	"github.com/spf13/viper"
)

type appConfig struct {
	Proxy struct {
		Transport         string `mapstructure:"transport"`
		Upstream          string `mapstructure:"upstream"`
		Port              int    `mapstructure:"port"`
		UpstreamTimeoutMS int    `mapstructure:"upstream_timeout_ms"`
		ClientID          string `mapstructure:"client_id"`
		ServerID          string `mapstructure:"server_id"`
	} `mapstructure:"proxy"`
	Audit struct {
		Storage    string `mapstructure:"storage"`
		Path       string `mapstructure:"path"`
		SQLitePath string `mapstructure:"sqlite_path"`
		Sign       bool   `mapstructure:"sign"`
		Secret     string `mapstructure:"secret"`
		Async      struct {
			Enabled         bool `mapstructure:"enabled"`
			QueueSize       int  `mapstructure:"queue_size"`
			BatchSize       int  `mapstructure:"batch_size"`
			FlushIntervalMS int  `mapstructure:"flush_interval_ms"`
		} `mapstructure:"async"`
	} `mapstructure:"audit"`
	Middleware struct {
		RateLimit struct {
			Enabled           bool `mapstructure:"enabled"`
			RequestsPerMinute int  `mapstructure:"requests_per_minute"`
		} `mapstructure:"rate_limit"`
		Redact struct {
			Enabled  bool     `mapstructure:"enabled"`
			Patterns []string `mapstructure:"patterns"`
		} `mapstructure:"redact"`
	} `mapstructure:"middleware"`
	Policy struct {
		Enabled       bool          `mapstructure:"enabled"`
		DefaultAction string        `mapstructure:"default_action"`
		Rules         []policy.Rule `mapstructure:"rules"`
	} `mapstructure:"policy"`
	Dashboard struct {
		Enabled bool `mapstructure:"enabled"`
		Port    int  `mapstructure:"port"`
	} `mapstructure:"dashboard"`
	Metrics struct {
		Enabled               bool   `mapstructure:"enabled"`
		Port                  int    `mapstructure:"port"`
		Path                  string `mapstructure:"path"`
		IncludeGoMetrics      bool   `mapstructure:"include_go_metrics"`
		IncludeProcessMetrics bool   `mapstructure:"include_process_metrics"`
		ToolLabels            bool   `mapstructure:"tool_labels"`
	} `mapstructure:"metrics"`
	OTel struct {
		Enabled     bool              `mapstructure:"enabled"`
		Endpoint    string            `mapstructure:"endpoint"`
		ServiceName string            `mapstructure:"service_name"`
		Headers     map[string]string `mapstructure:"headers"`
		TLS         struct {
			CAFile             string `mapstructure:"ca_file"`
			ServerName         string `mapstructure:"server_name"`
			InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
		} `mapstructure:"tls"`
		Retry struct {
			MaxRetries        int `mapstructure:"max_retries"`
			InitialIntervalMS int `mapstructure:"initial_interval_ms"`
			MaxIntervalMS     int `mapstructure:"max_interval_ms"`
		} `mapstructure:"retry"`
		QueueSize       int `mapstructure:"queue_size"`
		BatchSize       int `mapstructure:"batch_size"`
		FlushIntervalMS int `mapstructure:"flush_interval_ms"`
		TimeoutMS       int `mapstructure:"timeout_ms"`
	} `mapstructure:"otel"`
}

type cliFlags struct {
	config      string
	transport   string
	upstream    string
	port        int
	timeout     int
	storage     string
	noDashboard bool
	noMetrics   bool
	logLevel    string
	set         map[string]bool
}

func main() {
	flags := parseFlags()
	logger := newLogger(flags.logLevel)
	config, err := loadConfig(flags)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	logger = newLogger(configuredLogLevel(flags))

	metricsRecorder, metricsServer, err := newMetrics(config, logger)
	if err != nil {
		logger.Error("failed to initialize metrics", "error", err)
		os.Exit(1)
	}
	traceExporter, err := newTraceExporter(config, metricsRecorder, logger)
	if err != nil {
		logger.Error("failed to initialize otel exporter", "error", err)
		os.Exit(1)
	}
	if traceExporter != nil {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := traceExporter.Close(shutdownCtx); err != nil {
				logger.Warn("failed to close otel exporter", "error", err)
			}
		}()
	}

	store, err := openStore(config, metricsRecorder)
	if err != nil {
		logger.Error("failed to open audit store", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("failed to close audit store", "error", err)
		}
	}()

	secret := config.Audit.Secret
	if envSecret := os.Getenv("AUDIT_SECRET"); envSecret != "" {
		secret = envSecret
	}
	var signer *audit.Signer
	if config.Audit.Sign {
		signer = audit.NewSigner(secret)
	}
	redactor := middleware.NewRedactor(config.Middleware.Redact.Enabled, config.Middleware.Redact.Patterns)
	policyEngine, err := newPolicy(config)
	if err != nil {
		logger.Error("failed to initialize policy engine", "error", err)
		os.Exit(1)
	}
	auditLogger := audit.NewLogger(audit.LoggerConfig{
		Store:     store,
		Signer:    signer,
		Redactor:  redactor,
		Log:       logger,
		Transport: config.Proxy.Transport,
		ClientID:  config.Proxy.ClientID,
		ServerID:  config.Proxy.ServerID,
		Metrics:   metricsRecorder,
		Trace:     traceExporter,
	})
	limiter := middleware.NewRateLimiter(config.Middleware.RateLimit.Enabled, config.Middleware.RateLimit.RequestsPerMinute)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 3)
	if config.Dashboard.Enabled {
		server := dashboard.NewServer(dashboard.Config{
			Enabled: true,
			Port:    config.Dashboard.Port,
			Store:   store,
			Log:     logger,
		})
		go func() {
			errs <- server.ListenAndServe(ctx)
		}()
		logger.Info("dashboard listening", "port", config.Dashboard.Port)
	}
	if metricsServer != nil {
		go func() {
			errs <- metricsServer.ListenAndServe(ctx)
		}()
		logger.Info("metrics listening", "port", config.Metrics.Port, "path", config.Metrics.Path)
	}

	switch config.Proxy.Transport {
	case "stdio":
		stdio := proxy.NewStdioProxy(proxy.StdioConfig{
			Upstream: config.Proxy.Upstream,
			Audit:    auditLogger,
			Limiter:  limiter,
			Policy:   policyEngine,
			Log:      logger,
			ClientID: config.Proxy.ClientID,
			ServerID: config.Proxy.ServerID,
			Metrics:  metricsRecorder,
		})
		err = stdio.Run(ctx)
	case "http":
		httpProxy, err := proxy.NewHTTPProxy(proxy.HTTPConfig{
			Upstream:          config.Proxy.Upstream,
			Port:              config.Proxy.Port,
			UpstreamTimeoutMS: config.Proxy.UpstreamTimeoutMS,
			Audit:             auditLogger,
			Limiter:           limiter,
			Policy:            policyEngine,
			Log:               logger,
			ClientID:          config.Proxy.ClientID,
			ServerID:          config.Proxy.ServerID,
			Metrics:           metricsRecorder,
		})
		if err != nil {
			logger.Error("failed to create http proxy", "error", err)
			os.Exit(1)
		}
		logger.Info("http proxy listening", "port", config.Proxy.Port, "upstream", config.Proxy.Upstream)
		err = httpProxy.ListenAndServe(ctx)
	default:
		err = fmt.Errorf("main: unknown transport %q", config.Proxy.Transport)
	}
	stop()
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("proxy stopped with error", "error", err)
		os.Exit(1)
	}
	select {
	case err := <-errs:
		if err != nil {
			logger.Error("background server stopped with error", "error", err)
			os.Exit(1)
		}
	default:
	}
}

func parseFlags() cliFlags {
	flags := cliFlags{set: make(map[string]bool)}
	flag.StringVar(&flags.config, "config", "./config.yaml", "path to config.yaml")
	flag.StringVar(&flags.transport, "transport", "", "stdio or http")
	flag.StringVar(&flags.upstream, "upstream", "", "upstream server command or URL")
	flag.IntVar(&flags.port, "port", 0, "proxy port for http mode")
	flag.IntVar(&flags.timeout, "upstream-timeout", 0, "upstream HTTP request timeout in milliseconds")
	flag.StringVar(&flags.storage, "storage", "", "jsonl or sqlite")
	flag.BoolVar(&flags.noDashboard, "no-dashboard", false, "disable dashboard")
	flag.BoolVar(&flags.noMetrics, "no-metrics", false, "disable Prometheus metrics")
	flag.StringVar(&flags.logLevel, "log-level", "info", "debug, info, warn, or error")
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		flags.set[f.Name] = true
	})
	return flags
}

func loadConfig(flags cliFlags) (appConfig, error) {
	v := viper.New()
	setDefaults(v)
	v.SetConfigFile(flags.config)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) && !os.IsNotExist(err) {
			return appConfig{}, fmt.Errorf("main: read config: %w", err)
		}
	}
	applyFlagOverrides(v, flags)
	var config appConfig
	if err := v.Unmarshal(&config); err != nil {
		return appConfig{}, fmt.Errorf("main: decode config: %w", err)
	}
	return config, validateConfig(config)
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("proxy.transport", "stdio")
	v.SetDefault("proxy.port", 4422)
	v.SetDefault("proxy.upstream_timeout_ms", proxy.DefaultHTTPUpstreamTimeoutMS)
	v.SetDefault("proxy.client_id", "claude-desktop")
	v.SetDefault("proxy.server_id", "filesystem")
	v.SetDefault("audit.storage", "jsonl")
	v.SetDefault("audit.path", "./audit.jsonl")
	v.SetDefault("audit.sqlite_path", "./audit.db")
	v.SetDefault("audit.sign", true)
	v.SetDefault("audit.async.enabled", false)
	v.SetDefault("audit.async.queue_size", 4096)
	v.SetDefault("audit.async.batch_size", 128)
	v.SetDefault("audit.async.flush_interval_ms", 1000)
	v.SetDefault("middleware.rate_limit.enabled", true)
	v.SetDefault("middleware.rate_limit.requests_per_minute", 60)
	v.SetDefault("middleware.redact.enabled", true)
	v.SetDefault("middleware.redact.patterns", middleware.DefaultRedactPatterns)
	v.SetDefault("policy.enabled", false)
	v.SetDefault("policy.default_action", policy.ActionAllow)
	v.SetDefault("policy.rules", []policy.Rule{})
	v.SetDefault("dashboard.enabled", true)
	v.SetDefault("dashboard.port", 9090)
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.port", 9091)
	v.SetDefault("metrics.path", "/metrics")
	v.SetDefault("metrics.include_go_metrics", true)
	v.SetDefault("metrics.include_process_metrics", true)
	v.SetDefault("metrics.tool_labels", true)
	v.SetDefault("otel.enabled", false)
	v.SetDefault("otel.endpoint", "http://localhost:4318")
	v.SetDefault("otel.service_name", "mcp-audit")
	v.SetDefault("otel.headers", map[string]string{})
	v.SetDefault("otel.tls.ca_file", "")
	v.SetDefault("otel.tls.server_name", "")
	v.SetDefault("otel.tls.insecure_skip_verify", false)
	v.SetDefault("otel.retry.max_retries", 3)
	v.SetDefault("otel.retry.initial_interval_ms", 200)
	v.SetDefault("otel.retry.max_interval_ms", 2000)
	v.SetDefault("otel.queue_size", 1024)
	v.SetDefault("otel.batch_size", 64)
	v.SetDefault("otel.flush_interval_ms", 1000)
	v.SetDefault("otel.timeout_ms", 5000)
}

func applyFlagOverrides(v *viper.Viper, flags cliFlags) {
	if flags.set["transport"] {
		v.Set("proxy.transport", flags.transport)
	}
	if flags.set["upstream"] {
		v.Set("proxy.upstream", flags.upstream)
	}
	if flags.set["port"] {
		v.Set("proxy.port", flags.port)
	}
	if flags.set["upstream-timeout"] {
		v.Set("proxy.upstream_timeout_ms", flags.timeout)
	}
	if flags.set["storage"] {
		v.Set("audit.storage", flags.storage)
	}
	if flags.set["no-dashboard"] && flags.noDashboard {
		v.Set("dashboard.enabled", false)
	}
	if flags.set["no-metrics"] && flags.noMetrics {
		v.Set("metrics.enabled", false)
	}
}

func validateConfig(config appConfig) error {
	switch config.Proxy.Transport {
	case "stdio", "http":
	default:
		return fmt.Errorf("main: proxy.transport must be stdio or http")
	}
	if config.Proxy.Upstream == "" {
		return fmt.Errorf("main: proxy.upstream is required")
	}
	if config.Proxy.Transport == "http" && config.Proxy.UpstreamTimeoutMS <= 0 {
		return fmt.Errorf("main: proxy.upstream_timeout_ms must be > 0")
	}
	if config.Metrics.Path == "" || !strings.HasPrefix(config.Metrics.Path, "/") {
		return fmt.Errorf("main: metrics.path must start with /")
	}
	if config.OTel.Enabled {
		if config.OTel.Endpoint == "" {
			return fmt.Errorf("main: otel.endpoint is required when otel is enabled")
		}
		if config.OTel.Retry.MaxRetries < 0 {
			return fmt.Errorf("main: otel.retry.max_retries must be >= 0")
		}
	}
	switch config.Audit.Storage {
	case "jsonl", "sqlite":
	default:
		return fmt.Errorf("main: audit.storage must be jsonl or sqlite")
	}
	return nil
}

func newPolicy(config appConfig) (*policy.Engine, error) {
	if !config.Policy.Enabled {
		return nil, nil
	}
	return policy.NewEngine(policy.Config{
		Enabled:       config.Policy.Enabled,
		DefaultAction: config.Policy.DefaultAction,
		Rules:         config.Policy.Rules,
	})
}

func newMetrics(config appConfig, logger *slog.Logger) (metrics.Recorder, *metrics.PrometheusRecorder, error) {
	if !config.Metrics.Enabled {
		return metrics.Noop(), nil, nil
	}
	recorder, err := metrics.NewPrometheusRecorder(metrics.Config{
		Enabled:               true,
		Port:                  config.Metrics.Port,
		Path:                  config.Metrics.Path,
		IncludeGoMetrics:      config.Metrics.IncludeGoMetrics,
		IncludeProcessMetrics: config.Metrics.IncludeProcessMetrics,
		ToolLabels:            config.Metrics.ToolLabels,
		Log:                   logger,
	})
	if err != nil {
		return nil, nil, err
	}
	return recorder, recorder, nil
}

func newTraceExporter(config appConfig, metricsRecorder metrics.Recorder, logger *slog.Logger) (*otel.Exporter, error) {
	if !config.OTel.Enabled {
		return nil, nil
	}
	return otel.NewExporter(otel.Config{
		Enabled:               true,
		Endpoint:              config.OTel.Endpoint,
		ServiceName:           config.OTel.ServiceName,
		Storage:               config.Audit.Storage,
		Upstream:              config.Proxy.Upstream,
		Headers:               config.OTel.Headers,
		TLSCAFile:             config.OTel.TLS.CAFile,
		TLSServerName:         config.OTel.TLS.ServerName,
		TLSInsecureSkipVerify: config.OTel.TLS.InsecureSkipVerify,
		MaxRetries:            config.OTel.Retry.MaxRetries,
		RetryInitialMS:        config.OTel.Retry.InitialIntervalMS,
		RetryMaxMS:            config.OTel.Retry.MaxIntervalMS,
		QueueSize:             config.OTel.QueueSize,
		BatchSize:             config.OTel.BatchSize,
		FlushIntervalMS:       config.OTel.FlushIntervalMS,
		TimeoutMS:             config.OTel.TimeoutMS,
		Metrics:               metricsRecorder,
		Log:                   logger,
	})
}

func openStore(config appConfig, metricsRecorder metrics.Recorder) (audit.Store, error) {
	var store audit.Store
	backend := config.Audit.Storage
	switch config.Audit.Storage {
	case "jsonl":
		jsonl, err := storage.NewJSONLStore(config.Audit.Path)
		if err != nil {
			return nil, err
		}
		store = jsonl
	case "sqlite":
		sqlite, err := storage.NewSQLiteStore(config.Audit.SQLitePath)
		if err != nil {
			return nil, err
		}
		store = sqlite
	default:
		return nil, fmt.Errorf("main: unknown storage backend %q", config.Audit.Storage)
	}
	if config.Audit.Async.Enabled {
		store = storage.NewInstrumentedStore(store, metricsRecorder, backend, "async")
		store = storage.NewAsyncStoreWithMetrics(store, storage.AsyncConfig{
			QueueSize:       config.Audit.Async.QueueSize,
			BatchSize:       config.Audit.Async.BatchSize,
			FlushIntervalMS: config.Audit.Async.FlushIntervalMS,
		}, metricsRecorder)
	} else {
		store = storage.NewInstrumentedStore(store, metricsRecorder, backend, "sync")
	}
	return store, nil
}

func newLogger(level string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slogLevel}))
}

func configuredLogLevel(flags cliFlags) string {
	if flags.logLevel == "" {
		return "info"
	}
	return flags.logLevel
}
