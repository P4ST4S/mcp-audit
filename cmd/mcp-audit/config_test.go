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
