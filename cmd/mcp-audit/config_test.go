package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/dashboard"
	"github.com/P4ST4S/mcp-audit/internal/proxy"
)

// TestLoadConfigUsesDefaultUpstreamTimeout verifies the HTTP upstream timeout
// default is applied when neither config nor flags specify it.
func TestLoadConfigUsesDefaultUpstreamTimeout(t *testing.T) {
	config, err := loadConfig(cliFlags{
		config:   filepath.Join(t.TempDir(), "missing.yaml"),
		upstream: "cat",
		set: map[string]bool{
			"upstream": true,
		},
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.Proxy.UpstreamTimeoutMS != proxy.DefaultHTTPUpstreamTimeoutMS {
		t.Fatalf("upstream timeout = %d, want %d", config.Proxy.UpstreamTimeoutMS, proxy.DefaultHTTPUpstreamTimeoutMS)
	}
	if config.Dashboard.BindAddress != dashboard.DefaultBindAddress {
		t.Fatalf("dashboard bind address = %q, want %q", config.Dashboard.BindAddress, dashboard.DefaultBindAddress)
	}
	if config.Dashboard.Auth.Token != "" {
		t.Fatalf("dashboard auth token = %q, want empty", config.Dashboard.Auth.Token)
	}
	if len(config.Proxy.ForwardHeaders) != 0 {
		t.Fatalf("forward_headers = %#v, want empty", config.Proxy.ForwardHeaders)
	}
}

// TestLoadConfigReadsUpstreamTimeout verifies config.yaml can set the HTTP
// upstream timeout.
func TestLoadConfigReadsUpstreamTimeout(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("proxy:\n  upstream: cat\n  upstream_timeout_ms: 100\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := loadConfig(cliFlags{
		config: configPath,
		set:    map[string]bool{},
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.Proxy.UpstreamTimeoutMS != 100 {
		t.Fatalf("upstream timeout = %d, want 100", config.Proxy.UpstreamTimeoutMS)
	}
}

func TestLoadConfigReadsProxyTLSAndRetry(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte(`proxy:
  upstream: https://upstream.local
  forward_headers:
    - Authorization
  tls:
    ca_file: /tmp/ca.pem
    server_name: mcp.internal
    insecure_skip_verify: true
    client_cert_file: /tmp/client.crt
    client_key_file: /tmp/client.key
  retry:
    max_retries: 2
    initial_interval_ms: 50
    max_interval_ms: 500
`)
	if err := os.WriteFile(configPath, raw, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := loadConfig(cliFlags{
		config: configPath,
		set:    map[string]bool{},
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.Proxy.TLS.CAFile != "/tmp/ca.pem" {
		t.Fatalf("ca_file = %q", config.Proxy.TLS.CAFile)
	}
	if config.Proxy.TLS.ServerName != "mcp.internal" {
		t.Fatalf("server_name = %q", config.Proxy.TLS.ServerName)
	}
	if !config.Proxy.TLS.InsecureSkipVerify {
		t.Fatal("insecure_skip_verify = false, want true")
	}
	if config.Proxy.TLS.ClientCertFile != "/tmp/client.crt" || config.Proxy.TLS.ClientKeyFile != "/tmp/client.key" {
		t.Fatalf("client cert/key = %q/%q", config.Proxy.TLS.ClientCertFile, config.Proxy.TLS.ClientKeyFile)
	}
	if config.Proxy.Retry.MaxRetries != 2 {
		t.Fatalf("max_retries = %d, want 2", config.Proxy.Retry.MaxRetries)
	}
	if config.Proxy.Retry.InitialIntervalMS != 50 {
		t.Fatalf("initial_interval_ms = %d, want 50", config.Proxy.Retry.InitialIntervalMS)
	}
	if config.Proxy.Retry.MaxIntervalMS != 500 {
		t.Fatalf("max_interval_ms = %d, want 500", config.Proxy.Retry.MaxIntervalMS)
	}
	if len(config.Proxy.ForwardHeaders) != 1 || config.Proxy.ForwardHeaders[0] != "Authorization" {
		t.Fatalf("forward_headers = %#v, want [Authorization]", config.Proxy.ForwardHeaders)
	}
}

func TestLoadConfigReadsDashboardBindAddressAndAuthToken(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte(`proxy:
  upstream: cat
dashboard:
  bind_address: 0.0.0.0
  port: 19090
  auth:
    token: dashboard-token
`)
	if err := os.WriteFile(configPath, raw, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := loadConfig(cliFlags{
		config: configPath,
		set:    map[string]bool{},
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.Dashboard.BindAddress != "0.0.0.0" {
		t.Fatalf("dashboard bind address = %q, want 0.0.0.0", config.Dashboard.BindAddress)
	}
	if config.Dashboard.Port != 19090 {
		t.Fatalf("dashboard port = %d, want 19090", config.Dashboard.Port)
	}
	if config.Dashboard.Auth.Token != "dashboard-token" {
		t.Fatalf("dashboard auth token = %q, want dashboard-token", config.Dashboard.Auth.Token)
	}
}

func TestLoadConfigReadsAuditRotation(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte(`proxy:
  upstream: cat
audit:
  rotation:
    max_size_bytes: 1024
    max_files: 3
    interval: daily
    max_age_days: 30
`)
	if err := os.WriteFile(configPath, raw, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := loadConfig(cliFlags{
		config: configPath,
		set:    map[string]bool{},
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.Audit.Rotation.MaxSizeBytes != 1024 {
		t.Fatalf("max_size_bytes = %d, want 1024", config.Audit.Rotation.MaxSizeBytes)
	}
	if config.Audit.Rotation.MaxFiles != 3 {
		t.Fatalf("max_files = %d, want 3", config.Audit.Rotation.MaxFiles)
	}
	if config.Audit.Rotation.Interval != "daily" {
		t.Fatalf("interval = %q, want daily", config.Audit.Rotation.Interval)
	}
	if config.Audit.Rotation.MaxAgeDays != 30 {
		t.Fatalf("max_age_days = %d, want 30", config.Audit.Rotation.MaxAgeDays)
	}
}

func TestLoadConfigAuditRotationDefaults(t *testing.T) {
	config, err := loadConfig(cliFlags{
		config:   filepath.Join(t.TempDir(), "missing.yaml"),
		upstream: "cat",
		set: map[string]bool{
			"upstream": true,
		},
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.Audit.Rotation.Interval != "" {
		t.Fatalf("interval = %q, want empty", config.Audit.Rotation.Interval)
	}
	if config.Audit.Rotation.MaxAgeDays != 0 {
		t.Fatalf("max_age_days = %d, want 0", config.Audit.Rotation.MaxAgeDays)
	}
}

// TestLoadConfigUpstreamTimeoutFlagOverridesConfig verifies the CLI flag has
// higher precedence than config.yaml for the HTTP upstream timeout.
func TestLoadConfigUpstreamTimeoutFlagOverridesConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("proxy:\n  upstream: cat\n  upstream_timeout_ms: 100\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := loadConfig(cliFlags{
		config:  configPath,
		timeout: 250,
		set: map[string]bool{
			"upstream-timeout": true,
		},
	})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.Proxy.UpstreamTimeoutMS != 250 {
		t.Fatalf("upstream timeout = %d, want 250", config.Proxy.UpstreamTimeoutMS)
	}
}

// TestValidateConfigRejectsInvalidUpstreamTimeout verifies HTTP mode rejects a
// non-positive upstream timeout.
func TestValidateConfigRejectsInvalidUpstreamTimeout(t *testing.T) {
	config := appConfig{}
	config.Proxy.Transport = "http"
	config.Proxy.Upstream = "http://localhost:8080"

	if err := validateConfig(config); err == nil {
		t.Fatal("expected invalid upstream timeout error, got nil")
	}
}

func TestValidateConfigRejectsInvalidProxyRetry(t *testing.T) {
	config := appConfig{}
	config.Proxy.Transport = "http"
	config.Proxy.Upstream = "http://localhost:8080"
	config.Proxy.UpstreamTimeoutMS = 100
	config.Proxy.Retry.MaxRetries = -1
	config.Audit.Storage = "jsonl"
	config.Metrics.Path = "/metrics"

	if err := validateConfig(config); err == nil {
		t.Fatal("expected invalid retry config error, got nil")
	}
}

func TestValidateConfigRejectsPartialProxyMTLSConfig(t *testing.T) {
	config := appConfig{}
	config.Proxy.Transport = "http"
	config.Proxy.Upstream = "https://localhost:8080"
	config.Proxy.UpstreamTimeoutMS = 100
	config.Proxy.TLS.ClientCertFile = "/tmp/client.crt"
	config.Audit.Storage = "jsonl"
	config.Metrics.Path = "/metrics"

	if err := validateConfig(config); err == nil {
		t.Fatal("expected partial mTLS config error, got nil")
	}
}

func TestValidateConfigRejectsInvalidAuditRotation(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*appConfig)
	}{
		{
			name: "negative max size",
			configure: func(config *appConfig) {
				config.Audit.Rotation.MaxSizeBytes = -1
			},
		},
		{
			name: "negative max files",
			configure: func(config *appConfig) {
				config.Audit.Rotation.MaxFiles = -1
			},
		},
		{
			name: "negative max age days",
			configure: func(config *appConfig) {
				config.Audit.Rotation.MaxAgeDays = -1
			},
		},
		{
			name: "invalid interval",
			configure: func(config *appConfig) {
				config.Audit.Rotation.Interval = "weekly"
			},
		},
		{
			name: "sqlite size rotation",
			configure: func(config *appConfig) {
				config.Audit.Storage = "sqlite"
				config.Audit.Rotation.MaxSizeBytes = 1024
			},
		},
		{
			name: "sqlite time rotation",
			configure: func(config *appConfig) {
				config.Audit.Storage = "sqlite"
				config.Audit.Rotation.Interval = "daily"
			},
		},
		{
			name: "sqlite age retention",
			configure: func(config *appConfig) {
				config.Audit.Storage = "sqlite"
				config.Audit.Rotation.MaxAgeDays = 30
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := minimalValidConfig()
			tc.configure(&config)
			if err := validateConfig(config); err == nil {
				t.Fatal("expected invalid audit rotation config error, got nil")
			}
		})
	}
}

func TestValidateConfigRejectsInvalidForwardHeaders(t *testing.T) {
	cases := []struct {
		name    string
		headers []string
	}{
		{name: "empty", headers: []string{""}},
		{name: "leading whitespace", headers: []string{" Authorization"}},
		{name: "trailing whitespace", headers: []string{"Authorization "}},
		{name: "embedded whitespace", headers: []string{"X Auth"}},
		{name: "cookie", headers: []string{"Cookie"}},
		{name: "set-cookie case insensitive", headers: []string{"set-cookie"}},
		{name: "proxy authorization", headers: []string{"Proxy-Authorization"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := minimalValidConfig()
			config.Proxy.ForwardHeaders = tc.headers
			if err := validateConfig(config); err == nil {
				t.Fatal("expected invalid forward headers error, got nil")
			}
		})
	}
}

func TestValidateConfigAllowsAuthorizationForwardHeader(t *testing.T) {
	config := minimalValidConfig()
	config.Proxy.ForwardHeaders = []string{"Authorization"}

	if err := validateConfig(config); err != nil {
		t.Fatalf("validate config: %v", err)
	}
}

func TestValidateConfigRejectsInvalidDashboardConfig(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*appConfig)
	}{
		{
			name: "missing bind address",
			configure: func(config *appConfig) {
				config.Dashboard.BindAddress = ""
			},
		},
		{
			name: "zero port",
			configure: func(config *appConfig) {
				config.Dashboard.Port = 0
			},
		},
		{
			name: "port above range",
			configure: func(config *appConfig) {
				config.Dashboard.Port = 65536
			},
		},
		{
			name: "token with leading whitespace",
			configure: func(config *appConfig) {
				config.Dashboard.Auth.Token = " dashboard-token"
			},
		},
		{
			name: "token with embedded whitespace",
			configure: func(config *appConfig) {
				config.Dashboard.Auth.Token = "dashboard token"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := minimalValidConfig()
			tc.configure(&config)
			if err := validateConfig(config); err == nil {
				t.Fatal("expected invalid dashboard config error, got nil")
			}
		})
	}
}

func TestValidateConfigAllowsDashboardAuthToken(t *testing.T) {
	config := minimalValidConfig()
	config.Dashboard.Auth.Token = "dashboard-token"

	if err := validateConfig(config); err != nil {
		t.Fatalf("validate config: %v", err)
	}
}

func TestDashboardConfigFromAppMapsRuntimeConfig(t *testing.T) {
	config := minimalValidConfig()
	config.Dashboard.BindAddress = "0.0.0.0"
	config.Dashboard.Port = 19090
	config.Dashboard.Auth.Token = "dashboard-token"
	store := &cmdMemoryStore{}
	logger := slog.Default()

	dashboardConfig := dashboardConfigFromApp(config, store, logger)

	if !dashboardConfig.Enabled {
		t.Fatal("dashboard enabled = false, want true")
	}
	if dashboardConfig.BindAddress != "0.0.0.0" {
		t.Fatalf("bind address = %q, want 0.0.0.0", dashboardConfig.BindAddress)
	}
	if dashboardConfig.Port != 19090 {
		t.Fatalf("port = %d, want 19090", dashboardConfig.Port)
	}
	if dashboardConfig.Auth.Token != "dashboard-token" {
		t.Fatalf("auth token = %q, want dashboard-token", dashboardConfig.Auth.Token)
	}
	if dashboardConfig.Store != store {
		t.Fatal("store was not propagated")
	}
	if dashboardConfig.Log != logger {
		t.Fatal("logger was not propagated")
	}
}

// TestValidateConfigAllowsUnsetStdioUpstreamTimeout verifies the HTTP-only
// timeout validation does not affect stdio mode.
func TestValidateConfigAllowsUnsetStdioUpstreamTimeout(t *testing.T) {
	config := minimalValidConfig()
	config.Proxy.UpstreamTimeoutMS = 0

	if err := validateConfig(config); err != nil {
		t.Fatalf("validate config: %v", err)
	}
}

func minimalValidConfig() appConfig {
	config := appConfig{}
	config.Proxy.Transport = "stdio"
	config.Proxy.Upstream = "cat"
	config.Audit.Storage = "jsonl"
	config.Metrics.Path = "/metrics"
	config.Dashboard.Enabled = true
	config.Dashboard.BindAddress = dashboard.DefaultBindAddress
	config.Dashboard.Port = 9090
	return config
}

type cmdMemoryStore struct{}

func (s *cmdMemoryStore) Append(audit.Entry) error { return nil }

func (s *cmdMemoryStore) Query(audit.QueryFilter) ([]audit.Entry, error) {
	return nil, nil
}

func (s *cmdMemoryStore) Stats() (audit.Stats, error) { return audit.Stats{}, nil }

func (s *cmdMemoryStore) Close() error { return nil }
