package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	auditintegrity "github.com/P4ST4S/mcp-audit/internal/audit/integrity"
	"github.com/P4ST4S/mcp-audit/internal/audit/storage"
	"github.com/P4ST4S/mcp-audit/internal/auth"
	"github.com/P4ST4S/mcp-audit/internal/dashboard"
	"github.com/P4ST4S/mcp-audit/internal/httpclient"
	"github.com/P4ST4S/mcp-audit/internal/metrics"
	"github.com/P4ST4S/mcp-audit/internal/middleware"
	"github.com/P4ST4S/mcp-audit/internal/otel"
	"github.com/P4ST4S/mcp-audit/internal/policy"
	"github.com/P4ST4S/mcp-audit/internal/proxy"
	"github.com/spf13/viper"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

const (
	preferredSigningSecretEnv = "MCP_AUDIT_SIGNING_SECRET"
	legacySigningSecretEnv    = "AUDIT_SECRET"
	recommendedSecretBytes    = 32
)

type appConfig struct {
	Proxy struct {
		Transport         string   `mapstructure:"transport"`
		Upstream          string   `mapstructure:"upstream"`
		BindAddress       string   `mapstructure:"bind_address"`
		Port              int      `mapstructure:"port"`
		UpstreamTimeoutMS int      `mapstructure:"upstream_timeout_ms"`
		ForwardHeaders    []string `mapstructure:"forward_headers"`
		HTTP              struct {
			MaxRequestBodyBytes int64         `mapstructure:"max_request_body_bytes"`
			MaxHeaderBytes      int           `mapstructure:"max_header_bytes"`
			ReadHeaderTimeout   time.Duration `mapstructure:"read_header_timeout"`
			ReadTimeout         time.Duration `mapstructure:"read_timeout"`
			WriteTimeout        time.Duration `mapstructure:"write_timeout"`
			IdleTimeout         time.Duration `mapstructure:"idle_timeout"`
			AllowedOrigins      []string      `mapstructure:"allowed_origins"`
			AllowedHosts        []string      `mapstructure:"allowed_hosts"`
		} `mapstructure:"http"`
		TLS struct {
			Enabled            bool   `mapstructure:"enabled"`
			CertFile           string `mapstructure:"cert_file"`
			KeyFile            string `mapstructure:"key_file"`
			CAFile             string `mapstructure:"ca_file"`
			ServerName         string `mapstructure:"server_name"`
			InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
			ClientCertFile     string `mapstructure:"client_cert_file"`
			ClientKeyFile      string `mapstructure:"client_key_file"`
		} `mapstructure:"tls"`
		Retry struct {
			MaxRetries        int `mapstructure:"max_retries"`
			InitialIntervalMS int `mapstructure:"initial_interval_ms"`
			MaxIntervalMS     int `mapstructure:"max_interval_ms"`
		} `mapstructure:"retry"`
		ClientID string `mapstructure:"client_id"`
		ServerID string `mapstructure:"server_id"`
	} `mapstructure:"proxy"`
	Auth struct {
		Mode   string `mapstructure:"mode"`
		Static struct {
			BearerToken string   `mapstructure:"bearer_token"`
			Subject     string   `mapstructure:"subject"`
			ClientID    string   `mapstructure:"client_id"`
			Issuer      string   `mapstructure:"issuer"`
			Roles       []string `mapstructure:"roles"`
			Scopes      []string `mapstructure:"scopes"`
		} `mapstructure:"static"`
		OIDC struct {
			Issuer          string        `mapstructure:"issuer"`
			Audience        string        `mapstructure:"audience"`
			JWKSURI         string        `mapstructure:"jwks_uri"`
			ClientIDClaim   string        `mapstructure:"client_id_claim"`
			RolesClaim      string        `mapstructure:"roles_claim"`
			ScopesClaim     string        `mapstructure:"scopes_claim"`
			AllowedMethods  []string      `mapstructure:"allowed_methods"`
			ClockSkew       time.Duration `mapstructure:"clock_skew"`
			HTTPTimeout     time.Duration `mapstructure:"http_timeout"`
			RefreshInterval time.Duration `mapstructure:"refresh_interval"`
		} `mapstructure:"oidc"`
	} `mapstructure:"auth"`
	Audit struct {
		Storage    string `mapstructure:"storage"`
		Path       string `mapstructure:"path"`
		SQLitePath string `mapstructure:"sqlite_path"`
		Sign       bool   `mapstructure:"sign"`
		Secret     string `mapstructure:"secret"`
		Signing    struct {
			KeyID string `mapstructure:"key_id"`
		} `mapstructure:"signing"`
		Async struct {
			Enabled         bool `mapstructure:"enabled"`
			QueueSize       int  `mapstructure:"queue_size"`
			BatchSize       int  `mapstructure:"batch_size"`
			FlushIntervalMS int  `mapstructure:"flush_interval_ms"`
		} `mapstructure:"async"`
		Rotation struct {
			MaxSizeBytes int64  `mapstructure:"max_size_bytes"`
			MaxFiles     int    `mapstructure:"max_files"`
			Interval     string `mapstructure:"interval"`
			MaxAgeDays   int    `mapstructure:"max_age_days"`
		} `mapstructure:"rotation"`
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
		Scope         string        `mapstructure:"scope"`
		Rules         []policy.Rule `mapstructure:"rules"`
	} `mapstructure:"policy"`
	Dashboard struct {
		Enabled     bool   `mapstructure:"enabled"`
		BindAddress string `mapstructure:"bind_address"`
		Port        int    `mapstructure:"port"`
		Auth        struct {
			Token string `mapstructure:"token"`
		} `mapstructure:"auth"`
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
	version     bool
	logLevel    string
	set         map[string]bool
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		os.Exit(runVerifyCommand(os.Args[2:], os.Stdout, os.Stderr))
	}
	flags := parseFlags()
	if flags.version {
		fmt.Println(versionString())
		return
	}
	logger := newLogger(flags.logLevel)
	config, err := loadConfig(flags)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	logger = newLogger(configuredLogLevel(flags))
	if config.Proxy.Transport == "http" && strings.TrimSpace(config.Proxy.BindAddress) == "" {
		logger.Warn("proxy.bind_address is not configured; legacy all-interface binding is active")
	}
	if config.Audit.Sign && len([]byte(config.Audit.Secret)) < recommendedSecretBytes {
		logger.Warn("audit signing secret is shorter than the recommended minimum", "recommended_bytes", recommendedSecretBytes)
	}

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

	store, err := openStore(config, metricsRecorder, logger)
	if err != nil {
		logger.Error("failed to open audit store", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("failed to close audit store", "error", err)
		}
	}()

	var signer *audit.Signer
	var integritySigner *auditintegrity.Signer
	if config.Audit.Sign {
		signer = audit.NewSigner(config.Audit.Secret)
		integritySigner = auditintegrity.NewSigner(config.Audit.Secret, config.Audit.Signing.KeyID)
	}
	redactor := middleware.NewRedactor(config.Middleware.Redact.Enabled, config.Middleware.Redact.Patterns)
	policyEngine, err := newPolicy(config)
	if err != nil {
		logger.Error("failed to initialize policy engine", "error", err)
		os.Exit(1)
	}
	auditLogger := audit.NewLogger(audit.LoggerConfig{
		Store:           store,
		Signer:          signer,
		IntegritySigner: integritySigner,
		Redactor:        redactor,
		Log:             logger,
		Transport:       config.Proxy.Transport,
		ClientID:        config.Proxy.ClientID,
		ServerID:        config.Proxy.ServerID,
		Metrics:         metricsRecorder,
		Trace:           traceExporter,
	})
	limiter := middleware.NewRateLimiter(config.Middleware.RateLimit.Enabled, config.Middleware.RateLimit.RequestsPerMinute)
	authenticator, err := newAuthenticator(config)
	if err != nil {
		logger.Error("failed to initialize client authentication", "error", err)
		os.Exit(1)
	}
	if closer, ok := authenticator.(interface{ Close() error }); ok {
		defer func() {
			if err := closer.Close(); err != nil {
				logger.Warn("failed to close client authenticator", "error", err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 3)
	if config.Dashboard.Enabled {
		server := dashboard.NewServer(dashboardConfigFromApp(config, store, logger))
		go func() {
			errs <- server.ListenAndServe(ctx)
		}()
		logger.Info("dashboard listening", "bind_address", config.Dashboard.BindAddress, "port", config.Dashboard.Port, "auth_enabled", config.Dashboard.Auth.Token != "")
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
			Upstream:            config.Proxy.Upstream,
			BindAddress:         config.Proxy.BindAddress,
			Port:                config.Proxy.Port,
			UpstreamTimeoutMS:   config.Proxy.UpstreamTimeoutMS,
			ForwardHeaders:      config.Proxy.ForwardHeaders,
			MaxRequestBodyBytes: config.Proxy.HTTP.MaxRequestBodyBytes,
			MaxHeaderBytes:      config.Proxy.HTTP.MaxHeaderBytes,
			ReadHeaderTimeout:   config.Proxy.HTTP.ReadHeaderTimeout,
			ReadTimeout:         config.Proxy.HTTP.ReadTimeout,
			WriteTimeout:        config.Proxy.HTTP.WriteTimeout,
			IdleTimeout:         config.Proxy.HTTP.IdleTimeout,
			AllowedOrigins:      config.Proxy.HTTP.AllowedOrigins,
			AllowedHosts:        config.Proxy.HTTP.AllowedHosts,
			Authenticator:       authenticator,
			ServerTLS: proxy.HTTPServerTLSConfig{
				Enabled:  config.Proxy.TLS.Enabled,
				CertFile: config.Proxy.TLS.CertFile,
				KeyFile:  config.Proxy.TLS.KeyFile,
			},
			TLS: httpclient.TLSConfig{
				CAFile:             config.Proxy.TLS.CAFile,
				ServerName:         config.Proxy.TLS.ServerName,
				InsecureSkipVerify: config.Proxy.TLS.InsecureSkipVerify,
				ClientCertFile:     config.Proxy.TLS.ClientCertFile,
				ClientKeyFile:      config.Proxy.TLS.ClientKeyFile,
			},
			Retry: proxy.HTTPRetryConfig{
				MaxRetries:        config.Proxy.Retry.MaxRetries,
				InitialIntervalMS: config.Proxy.Retry.InitialIntervalMS,
				MaxIntervalMS:     config.Proxy.Retry.MaxIntervalMS,
			},
			Audit:    auditLogger,
			Limiter:  limiter,
			Policy:   policyEngine,
			Log:      logger,
			ClientID: config.Proxy.ClientID,
			ServerID: config.Proxy.ServerID,
			Metrics:  metricsRecorder,
		})
		if err != nil {
			logger.Error("failed to create http proxy", "error", err)
			os.Exit(1)
		}
		logger.Info("http proxy listening", "bind_address", config.Proxy.BindAddress, "port", config.Proxy.Port, "tls", config.Proxy.TLS.Enabled, "upstream", config.Proxy.Upstream)
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
	flag.BoolVar(&flags.version, "version", false, "print version and exit")
	flag.StringVar(&flags.logLevel, "log-level", "info", "debug, info, warn, or error")
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		flags.set[f.Name] = true
	})
	return flags
}

func versionString() string {
	resolvedVersion, resolvedCommit, resolvedDate := buildMetadata()
	return fmt.Sprintf("mcp-audit %s (commit %s, built %s)", resolvedVersion, resolvedCommit, resolvedDate)
}

func buildMetadata() (string, string, string) {
	resolvedVersion := version
	resolvedCommit := commit
	resolvedDate := date
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return resolvedVersion, resolvedCommit, resolvedDate
	}
	if (resolvedVersion == "" || resolvedVersion == "dev") && info.Main.Version != "" && info.Main.Version != "(devel)" {
		resolvedVersion = info.Main.Version
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if resolvedCommit == "" || resolvedCommit == "unknown" {
				resolvedCommit = setting.Value
			}
		case "vcs.time":
			if resolvedDate == "" || resolvedDate == "unknown" {
				resolvedDate = setting.Value
			}
		}
	}
	return resolvedVersion, resolvedCommit, resolvedDate
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
	if token := os.Getenv("MCP_AUDIT_STATIC_BEARER_TOKEN"); token != "" {
		config.Auth.Static.BearerToken = token
	}
	resolveSigningSecret(&config)
	return config, validateConfig(config)
}

func resolveSigningSecret(config *appConfig) {
	if legacySecret := os.Getenv(legacySigningSecretEnv); legacySecret != "" {
		config.Audit.Secret = legacySecret
	}
	if preferredSecret, configured := os.LookupEnv(preferredSigningSecretEnv); configured {
		config.Audit.Secret = preferredSecret
	}
}

func dashboardConfigFromApp(config appConfig, store audit.Store, logger *slog.Logger) dashboard.Config {
	return dashboard.Config{
		Enabled:     true,
		BindAddress: config.Dashboard.BindAddress,
		Port:        config.Dashboard.Port,
		Auth: dashboard.AuthConfig{
			Token: config.Dashboard.Auth.Token,
		},
		Store: store,
		Log:   logger,
	}
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("proxy.transport", "stdio")
	v.SetDefault("proxy.bind_address", "")
	v.SetDefault("proxy.port", 4422)
	v.SetDefault("proxy.upstream_timeout_ms", proxy.DefaultHTTPUpstreamTimeoutMS)
	v.SetDefault("proxy.forward_headers", []string{})
	v.SetDefault("proxy.http.max_request_body_bytes", proxy.DefaultHTTPMaxRequestBodyBytes)
	v.SetDefault("proxy.http.max_header_bytes", proxy.DefaultHTTPMaxHeaderBytes)
	v.SetDefault("proxy.http.read_header_timeout", proxy.DefaultHTTPReadHeaderTimeout)
	v.SetDefault("proxy.http.read_timeout", proxy.DefaultHTTPReadTimeout)
	v.SetDefault("proxy.http.write_timeout", proxy.DefaultHTTPWriteTimeout)
	v.SetDefault("proxy.http.idle_timeout", proxy.DefaultHTTPIdleTimeout)
	v.SetDefault("proxy.http.allowed_origins", []string{})
	v.SetDefault("proxy.http.allowed_hosts", []string{})
	v.SetDefault("proxy.tls.ca_file", "")
	v.SetDefault("proxy.tls.enabled", false)
	v.SetDefault("proxy.tls.cert_file", "")
	v.SetDefault("proxy.tls.key_file", "")
	v.SetDefault("proxy.tls.server_name", "")
	v.SetDefault("proxy.tls.insecure_skip_verify", false)
	v.SetDefault("proxy.tls.client_cert_file", "")
	v.SetDefault("proxy.tls.client_key_file", "")
	v.SetDefault("proxy.retry.max_retries", 0)
	v.SetDefault("proxy.retry.initial_interval_ms", 200)
	v.SetDefault("proxy.retry.max_interval_ms", 2000)
	v.SetDefault("proxy.client_id", "claude-desktop")
	v.SetDefault("proxy.server_id", "filesystem")
	v.SetDefault("auth.mode", auth.ModeNone)
	v.SetDefault("auth.static.bearer_token", "")
	v.SetDefault("auth.static.subject", "local")
	v.SetDefault("auth.static.client_id", "")
	v.SetDefault("auth.static.issuer", "static")
	v.SetDefault("auth.static.roles", []string{})
	v.SetDefault("auth.static.scopes", []string{})
	v.SetDefault("auth.oidc.issuer", "")
	v.SetDefault("auth.oidc.audience", "")
	v.SetDefault("auth.oidc.jwks_uri", "")
	v.SetDefault("auth.oidc.client_id_claim", "client_id")
	v.SetDefault("auth.oidc.roles_claim", "roles")
	v.SetDefault("auth.oidc.scopes_claim", "scope")
	v.SetDefault("auth.oidc.allowed_methods", []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"})
	v.SetDefault("auth.oidc.clock_skew", 30*time.Second)
	v.SetDefault("auth.oidc.http_timeout", 5*time.Second)
	v.SetDefault("auth.oidc.refresh_interval", 5*time.Minute)
	v.SetDefault("audit.storage", "jsonl")
	v.SetDefault("audit.path", "./audit.jsonl")
	v.SetDefault("audit.sqlite_path", "./audit.db")
	v.SetDefault("audit.sign", true)
	v.SetDefault("audit.signing.key_id", auditintegrity.DefaultKeyID)
	v.SetDefault("audit.async.enabled", false)
	v.SetDefault("audit.async.queue_size", 4096)
	v.SetDefault("audit.async.batch_size", 128)
	v.SetDefault("audit.async.flush_interval_ms", 1000)
	v.SetDefault("audit.rotation.max_size_bytes", 0)
	v.SetDefault("audit.rotation.max_files", 0)
	v.SetDefault("audit.rotation.interval", "")
	v.SetDefault("audit.rotation.max_age_days", 0)
	v.SetDefault("middleware.rate_limit.enabled", true)
	v.SetDefault("middleware.rate_limit.requests_per_minute", 60)
	v.SetDefault("middleware.redact.enabled", true)
	v.SetDefault("middleware.redact.patterns", middleware.DefaultRedactPatterns)
	v.SetDefault("policy.enabled", false)
	v.SetDefault("policy.default_action", policy.ActionAllow)
	v.SetDefault("policy.scope", policy.ScopeToolsOnly)
	v.SetDefault("policy.rules", []policy.Rule{})
	v.SetDefault("dashboard.enabled", true)
	v.SetDefault("dashboard.bind_address", dashboard.DefaultBindAddress)
	v.SetDefault("dashboard.port", 9090)
	v.SetDefault("dashboard.auth.token", "")
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
	if config.Proxy.Transport == "http" {
		if strings.TrimSpace(config.Proxy.BindAddress) != config.Proxy.BindAddress || strings.ContainsFunc(config.Proxy.BindAddress, unicode.IsSpace) {
			return fmt.Errorf("main: proxy.bind_address must not contain whitespace")
		}
		if config.Proxy.HTTP.MaxRequestBodyBytes <= 0 {
			return fmt.Errorf("main: proxy.http.max_request_body_bytes must be > 0")
		}
		if config.Proxy.HTTP.MaxHeaderBytes <= 0 {
			return fmt.Errorf("main: proxy.http.max_header_bytes must be > 0")
		}
		if config.Proxy.HTTP.ReadHeaderTimeout <= 0 || config.Proxy.HTTP.ReadTimeout <= 0 ||
			config.Proxy.HTTP.WriteTimeout <= 0 || config.Proxy.HTTP.IdleTimeout <= 0 {
			return fmt.Errorf("main: proxy.http timeouts must be > 0")
		}
		if err := proxy.ValidateHTTPAccessLists(config.Proxy.HTTP.AllowedOrigins, config.Proxy.HTTP.AllowedHosts); err != nil {
			return fmt.Errorf("main: %w", err)
		}
	}
	if config.Proxy.Retry.MaxRetries < 0 {
		return fmt.Errorf("main: proxy.retry.max_retries must be >= 0")
	}
	if err := validateForwardHeaders(config.Proxy.ForwardHeaders); err != nil {
		return err
	}
	if (config.Proxy.TLS.ClientCertFile == "") != (config.Proxy.TLS.ClientKeyFile == "") {
		return fmt.Errorf("main: proxy.tls.client_cert_file and proxy.tls.client_key_file must be configured together")
	}
	if config.Proxy.TLS.Enabled && config.Proxy.Transport != "http" {
		return fmt.Errorf("main: proxy.tls.enabled requires proxy.transport=http")
	}
	if config.Proxy.TLS.Enabled && (config.Proxy.TLS.CertFile == "" || config.Proxy.TLS.KeyFile == "") {
		return fmt.Errorf("main: proxy.tls.cert_file and proxy.tls.key_file are required when incoming TLS is enabled")
	}
	if !config.Proxy.TLS.Enabled && (config.Proxy.TLS.CertFile != "" || config.Proxy.TLS.KeyFile != "") {
		return fmt.Errorf("main: proxy.tls.cert_file and proxy.tls.key_file require proxy.tls.enabled=true")
	}
	if err := validateAuthConfig(config); err != nil {
		return err
	}
	if config.Metrics.Path == "" || !strings.HasPrefix(config.Metrics.Path, "/") {
		return fmt.Errorf("main: metrics.path must start with /")
	}
	if config.Dashboard.Enabled {
		if strings.TrimSpace(config.Dashboard.BindAddress) == "" {
			return fmt.Errorf("main: dashboard.bind_address is required when dashboard is enabled")
		}
		if config.Dashboard.Port <= 0 || config.Dashboard.Port > 65535 {
			return fmt.Errorf("main: dashboard.port must be between 1 and 65535")
		}
		if token := config.Dashboard.Auth.Token; token != "" {
			if strings.TrimSpace(token) != token || strings.ContainsFunc(token, unicode.IsSpace) {
				return fmt.Errorf("main: dashboard.auth.token must not contain whitespace")
			}
		}
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
	if keyID := config.Audit.Signing.KeyID; config.Audit.Sign &&
		(strings.TrimSpace(keyID) == "" || strings.ContainsFunc(keyID, unicode.IsSpace)) {
		return fmt.Errorf("main: audit.signing.key_id must be non-empty and contain no whitespace")
	}
	if config.Audit.Sign && strings.TrimSpace(config.Audit.Secret) == "" {
		return fmt.Errorf("main: audit signing is enabled but no signing secret is configured")
	}
	if config.Audit.Rotation.MaxSizeBytes < 0 {
		return fmt.Errorf("main: audit.rotation.max_size_bytes must be >= 0")
	}
	if config.Audit.Rotation.MaxFiles < 0 {
		return fmt.Errorf("main: audit.rotation.max_files must be >= 0")
	}
	if config.Audit.Rotation.MaxAgeDays < 0 {
		return fmt.Errorf("main: audit.rotation.max_age_days must be >= 0")
	}
	switch config.Audit.Rotation.Interval {
	case "", "hourly", "daily":
	default:
		return fmt.Errorf("main: audit.rotation.interval must be empty, hourly, or daily")
	}
	if config.Audit.Storage == "sqlite" && rotationConfigured(config) {
		return fmt.Errorf("main: audit.rotation is only supported with jsonl storage")
	}
	return nil
}

func validateAuthConfig(config appConfig) error {
	switch config.Auth.Mode {
	case auth.ModeNone:
		if err := validateStaticPrincipal(config); err != nil {
			return err
		}
		if config.Auth.Static.BearerToken != "" {
			return fmt.Errorf("main: auth.static.bearer_token requires auth.mode=static_bearer")
		}
	case auth.ModeStaticBearer:
		if err := validateStaticPrincipal(config); err != nil {
			return err
		}
		if config.Proxy.Transport != "http" {
			return fmt.Errorf("main: auth.mode=static_bearer requires proxy.transport=http")
		}
		if len(config.Auth.Static.BearerToken) < 32 {
			return fmt.Errorf("main: auth.static.bearer_token must be at least 32 bytes")
		}
	case auth.ModeOIDC:
		if config.Proxy.Transport != "http" {
			return fmt.Errorf("main: auth.mode=oidc requires proxy.transport=http")
		}
		if err := validateOIDCConfig(config); err != nil {
			return err
		}
	default:
		return fmt.Errorf("main: auth.mode must be none, static_bearer, or oidc")
	}
	return nil
}

func validateStaticPrincipal(config appConfig) error {
	clientID := config.Auth.Static.ClientID
	if clientID == "" {
		clientID = config.Proxy.ClientID
	}
	if config.Auth.Static.Subject == "" || clientID == "" {
		return fmt.Errorf("main: auth.static.subject and client_id are required")
	}
	return nil
}

func validateOIDCConfig(config appConfig) error {
	oidc := config.Auth.OIDC
	if oidc.Issuer == "" || oidc.Audience == "" || oidc.JWKSURI == "" {
		return fmt.Errorf("main: auth.oidc.issuer, audience, and jwks_uri are required")
	}
	issuer, err := url.Parse(oidc.Issuer)
	if err != nil || issuer.Hostname() == "" || (issuer.Scheme != "https" && issuer.Scheme != "http") || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return fmt.Errorf("main: auth.oidc.issuer must be an absolute HTTP(S) URL without userinfo, query, or fragment")
	}
	if issuer.Scheme == "http" && issuer.Hostname() != "localhost" && issuer.Hostname() != "127.0.0.1" && issuer.Hostname() != "::1" {
		return fmt.Errorf("main: auth.oidc.issuer must use HTTPS except on loopback")
	}
	parsed, err := url.Parse(oidc.JWKSURI)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("main: auth.oidc.jwks_uri must be an absolute HTTP(S) URL without userinfo or fragment")
	}
	if parsed.Scheme == "http" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" {
		return fmt.Errorf("main: auth.oidc.jwks_uri must use HTTPS except on loopback")
	}
	if oidc.ClientIDClaim == "" || oidc.RolesClaim == "" || oidc.ScopesClaim == "" {
		return fmt.Errorf("main: auth.oidc claim names must be non-empty")
	}
	if oidc.ClockSkew < 0 || oidc.HTTPTimeout <= 0 || oidc.RefreshInterval <= 0 {
		return fmt.Errorf("main: auth.oidc clock_skew must be non-negative and timeouts must be positive")
	}
	allowed := map[string]struct{}{"RS256": {}, "RS384": {}, "RS512": {}, "ES256": {}, "ES384": {}, "ES512": {}, "EdDSA": {}}
	if len(oidc.AllowedMethods) == 0 {
		return fmt.Errorf("main: auth.oidc.allowed_methods must be non-empty")
	}
	for _, method := range oidc.AllowedMethods {
		if _, ok := allowed[method]; !ok {
			return fmt.Errorf("main: auth.oidc.allowed_methods contains unsupported method %q", method)
		}
	}
	return nil
}

func newAuthenticator(config appConfig) (auth.Authenticator, error) {
	clientID := config.Auth.Static.ClientID
	if clientID == "" {
		clientID = config.Proxy.ClientID
	}
	principal := auth.Principal{
		Subject:  config.Auth.Static.Subject,
		ClientID: clientID,
		Issuer:   config.Auth.Static.Issuer,
		Roles:    config.Auth.Static.Roles,
		Scopes:   config.Auth.Static.Scopes,
	}
	switch config.Auth.Mode {
	case auth.ModeNone:
		return auth.NewNoneAuthenticator(principal)
	case auth.ModeStaticBearer:
		return auth.NewStaticBearerAuthenticator(config.Auth.Static.BearerToken, principal)
	case auth.ModeOIDC:
		return auth.NewJWTAuthenticator(context.Background(), auth.JWTAuthenticatorConfig{
			Issuer:          config.Auth.OIDC.Issuer,
			Audience:        config.Auth.OIDC.Audience,
			JWKSURI:         config.Auth.OIDC.JWKSURI,
			ClientIDClaim:   config.Auth.OIDC.ClientIDClaim,
			RolesClaim:      config.Auth.OIDC.RolesClaim,
			ScopesClaim:     config.Auth.OIDC.ScopesClaim,
			AllowedMethods:  config.Auth.OIDC.AllowedMethods,
			ClockSkew:       config.Auth.OIDC.ClockSkew,
			HTTPTimeout:     config.Auth.OIDC.HTTPTimeout,
			RefreshInterval: config.Auth.OIDC.RefreshInterval,
		})
	default:
		return nil, fmt.Errorf("main: unsupported auth mode %q", config.Auth.Mode)
	}
}

func rotationConfigured(config appConfig) bool {
	return config.Audit.Rotation.MaxSizeBytes > 0 ||
		config.Audit.Rotation.MaxFiles > 0 ||
		config.Audit.Rotation.Interval != "" ||
		config.Audit.Rotation.MaxAgeDays > 0
}

func validateForwardHeaders(headers []string) error {
	for _, header := range headers {
		if strings.TrimSpace(header) != header {
			return fmt.Errorf("main: proxy.forward_headers contains an invalid header name")
		}
		if header == "" {
			return fmt.Errorf("main: proxy.forward_headers contains an invalid header name")
		}
		if strings.ContainsFunc(header, unicode.IsSpace) {
			return fmt.Errorf("main: proxy.forward_headers header %q must not contain whitespace", header)
		}
		switch strings.ToLower(header) {
		case "cookie", "set-cookie", "proxy-authorization":
			return fmt.Errorf("main: proxy.forward_headers cannot include %q", header)
		}
	}
	return nil
}

func newPolicy(config appConfig) (*policy.Engine, error) {
	engine, err := policy.NewEngine(policy.Config{
		Enabled:       config.Policy.Enabled,
		DefaultAction: config.Policy.DefaultAction,
		Scope:         config.Policy.Scope,
		Rules:         config.Policy.Rules,
	})
	if err != nil {
		return nil, err
	}
	if !config.Policy.Enabled {
		return nil, nil
	}
	return engine, nil
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

func openStore(config appConfig, metricsRecorder metrics.Recorder, logger *slog.Logger) (audit.Store, error) {
	var store audit.Store
	backend := config.Audit.Storage
	switch config.Audit.Storage {
	case "jsonl":
		jsonl, err := storage.NewJSONLStoreWithConfig(config.Audit.Path, storage.JSONLConfig{
			MaxSizeBytes: config.Audit.Rotation.MaxSizeBytes,
			MaxFiles:     config.Audit.Rotation.MaxFiles,
			Interval:     config.Audit.Rotation.Interval,
			MaxAgeDays:   config.Audit.Rotation.MaxAgeDays,
			Log:          logger,
		})
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
