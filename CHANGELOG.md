# Changelog

All notable changes to mcp-audit are documented in this file.

## [Unreleased]

## [0.9.0] - 2026-05-29

### Added

- Cursor stdio configuration example under `examples/cursor/`.
- Docker Compose observability example with Prometheus and Grafana under `examples/docker-compose-observability/`.
- `--version` flag with release metadata injected at build time.
- GoReleaser configuration for Linux, macOS, and Windows binaries.
- SHA256 checksums for release archives.
- GitHub Actions release workflow for `v*` tags.
- Multi-stage non-root Docker image for `mcp-audit`.
- GHCR publishing workflow for multi-arch `linux/amd64` and `linux/arm64` images.
- README installation instructions for release binaries, Docker, and `go install`.

## [0.8.0] - 2026-05-29

### Added

- `proxy.upstream_timeout_ms` config and `--upstream-timeout` flag for HTTP upstream request timeout (default 30s).
- Cursor stdio configuration example under `examples/cursor/`.
- Formal security disclosure policy in `SECURITY.md`, with GitHub Security Advisories as the preferred private reporting channel.
- HTTP upstream TLS configuration, including custom CA bundles, server name override, local insecure verification, and optional mTLS client certificates.
- Conservative HTTP upstream retry configuration, disabled by default and limited to safe JSON-RPC methods (`tools/call` is never retried).
- Prometheus counter for HTTP upstream retry attempts by reason.

## [0.7.0] - 2026-05-28

### Added

- OTLP HTTP header configuration for authenticated collectors.
- OTLP TLS configuration for custom CA bundles, server name override, and local insecure verification.
- Bounded OTLP retry with exponential backoff and `Retry-After` support.
- Prometheus metrics for OTLP exports, dropped spans, and exporter queue depth/capacity.

## [0.6.1] - 2026-05-27

### Changed

- Centralized OpenTelemetry semantic convention attribute names in `internal/otel/semconv.go`.

## [0.6.0] - 2026-05-27

### Added

- OpenTelemetry OTLP/HTTP JSON trace export for `tools/call` audit entries.
- MCP and GenAI semantic convention attributes for exported spans.
- `otel.*` configuration for endpoint, service name, queueing, batching, and timeout.
- JSON-RPC request IDs in audit entries and OTLP span attributes when present.

## [0.5.0] - 2026-05-27

### Added

- Policy engine for synchronous allow/deny rules on `tools/call`.
- Ordered first-match policy rules by `client_id`, `server_id`, and `tool_name`.
- `policy.*` configuration for default action and rule definitions.
- JSON-RPC policy denial responses that are still written to the audit log.
- Prometheus counter for policy decisions by action.

## [0.4.0] - 2026-05-27

### Added

- Prometheus metrics endpoint on a separate port.
- Low-cardinality proxy, audit, storage, rate-limit, and async queue metrics.
- `metrics.*` configuration for enabling collectors and controlling tool labels.
- `--no-metrics` flag for disabling the metrics endpoint from the CLI.

## [0.3.0] - 2026-05-26

### Added

- Optional async audit write pipeline with a bounded ring buffer, batched writes, and explicit backpressure.
- Batched JSONL and SQLite storage writes.
- `audit.async.*` configuration for high-throughput deployments.

## [0.2.0] - 2026-05-25

### Added

- GitHub Actions CI workflow on push and pull requests.
- CI checks for `go build ./...`, `go vet ./...`, and `go test ./...`.
- End-to-end stdio integration test using `cat` as the upstream server.
- CI status badge in the README.

### Changed

- Tightened `.gitignore` so the root `mcp-audit` build binary is ignored
  without hiding files under `cmd/mcp-audit`.
- Updated the README install command to `v0.2.0`.

## [0.1.0] - 2026-05-24

### Added

- Transparent stdio and HTTP proxy support for MCP servers.
- HMAC-SHA256 signed audit entries.
- JSONL and SQLite audit storage backends.
- PII redaction middleware.
- Per-`(client, tool)` rate limiting with JSON-RPC error responses.
- Read-only web dashboard with auto-refresh.
- Graceful upstream shutdown for stdio mode.
- TTL cleanup for pending RPC state.
- Docker and Docker Compose support.
- Demo assets and MCP server metadata.
- Contribution guidelines.

### Known Limitations

- Experimental; not yet production tested at scale.
- Async write pipeline is not implemented.
- MCP Streamable HTTP transport is not supported.

[Unreleased]: https://github.com/P4ST4S/mcp-audit/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/P4ST4S/mcp-audit/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/P4ST4S/mcp-audit/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/P4ST4S/mcp-audit/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/P4ST4S/mcp-audit/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/P4ST4S/mcp-audit/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/P4ST4S/mcp-audit/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/P4ST4S/mcp-audit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/P4ST4S/mcp-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/P4ST4S/mcp-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/P4ST4S/mcp-audit/releases/tag/v0.1.0
