package main

import (
	"os"
	"path/filepath"
	"testing"

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

// TestValidateConfigAllowsUnsetStdioUpstreamTimeout verifies the HTTP-only
// timeout validation does not affect stdio mode.
func TestValidateConfigAllowsUnsetStdioUpstreamTimeout(t *testing.T) {
	config := appConfig{}
	config.Proxy.Transport = "stdio"
	config.Proxy.Upstream = "cat"
	config.Audit.Storage = "jsonl"
	config.Metrics.Path = "/metrics"

	if err := validateConfig(config); err != nil {
		t.Fatalf("validate config: %v", err)
	}
}
