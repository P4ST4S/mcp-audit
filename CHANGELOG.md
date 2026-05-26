# Changelog

All notable changes to mcp-audit are documented in this file.

## [Unreleased]

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

[Unreleased]: https://github.com/P4ST4S/mcp-audit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/P4ST4S/mcp-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/P4ST4S/mcp-audit/releases/tag/v0.1.0
