# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Codex, Jules, Amp, etc.) contributing to `mcp-audit`. Read this in full before opening a PR.

`mcp-audit` is a security and observability proxy for MCP (Model Context Protocol) servers, written in Go. It records signed audit trails, enforces policies, applies rate limits, and exports OTLP traces + Prometheus metrics. See [README.md](README.md) for what it does and why; this file is about how to work on it.

## Build, test, lint

```bash
go build ./...
go vet ./...
go test -race ./...
go test -race -coverprofile=coverage.out -covermode=atomic ./...
```

CI uses Go 1.22 (see `go.mod`). Tests must pass with `-race`. Coverage is uploaded to Codecov on push to `main`.

For local end-to-end testing, see the [`demo/`](demo/) directory and the [`run` skill in CLAUDE.md](CLAUDE.md) if applicable.

## Project layout

- `cmd/mcp-audit/` — CLI entry point and config loader (viper-based)
- `internal/audit/` — entry types, HMAC-SHA256 signing, storage interface
- `internal/audit/storage/` — `jsonl.go`, `sqlite.go`, `async.go`, `instrumented.go`
- `internal/proxy/` — `stdio.go` and `http.go` proxies, retry logic, TLS upstream support
- `internal/policy/` — allow/deny policy engine; emits JSON-RPC error code `-32030`
- `internal/middleware/` — rate limiter (per `client_id, tool_name` bucket; error code `-32029`) and PII redactor
- `internal/metrics/` — Prometheus recorder with stable metric names under `mcp_audit_*`
- `internal/otel/` — OTLP/HTTP JSON trace exporter (no SDK pulled in)
- `internal/httpclient/` — shared TLS-aware HTTP client used by proxy and OTel
- `internal/dashboard/` — read-only HTTP server (routes: `/`, `/api/entries`, `/api/stats`)

The split between `internal/` and the package boundary in `cmd/` is intentional: `internal/` is not importable by third parties. `internal/` packages can be refactored freely; the public CLI surface (config keys, flags, JSON-RPC error codes, audit JSON schema, metric names, OTLP attributes, dashboard API) is stable per [STABILITY.md](STABILITY.md).

## Code style

- **Standard Go formatting**: `gofmt`. `go vet` must pass.
- **Error wrapping**: prefer `fmt.Errorf("component: action: %w", err)` over bare returns. Errors should carry enough context that a stack trace isn't needed.
- **No new dependencies without justification**: this project prefers the standard library. If a new dep is required, mention it in the PR description and explain why stdlib was insufficient.
- **Thread safety**: any storage write path or shared state must be safe under concurrent use. Tests should pass with `-race`.
- **Comments**: only when the WHY is non-obvious. Don't restate the WHAT (a well-named function is its own doc). Document hidden invariants, performance trade-offs, or workarounds for specific bugs.

## Testing conventions

- Use `t.TempDir()` for any filesystem fixture. Never hardcode paths.
- Use `httptest.NewServer` for HTTP fakes. Never depend on a real external service.
- Tests must be deterministic and parallel-safe. No `time.Sleep` for synchronization; use channels or polling with a tight timeout.
- Prefer table-driven tests (`for _, tc := range cases { t.Run(tc.name, ...) }`) when the same logic is exercised against multiple inputs.
- Test the contract, not the implementation. A test that breaks when an internal function is renamed without a behavior change is a bad test.

See [`STORAGE_TESTS_PLAN.md`](STORAGE_TESTS_PLAN.md) for an example of the test-planning bar this project holds itself to.

## Guiding principles

These are non-negotiable design rules. A PR that violates one needs an exceptionally good reason.

1. **Zero accidental message drop.** The proxy MUST NOT drop or modify JSON-RPC messages because auditing or interception failed. If inspection fails, forward as-is and log the error separately. Intentional policy enforcement (rate limit, policy deny) must return a proper JSON-RPC error.
2. **Audit log is the evidence artifact.** Signed JSONL or SQLite rows are the durable record. OTel spans and Prometheus metrics are operational visibility, NOT evidence. Never make audit integrity depend on a side channel.
3. **`tools/call` is never retried automatically.** It is not safe to assume idempotency. Conservative retry (when enabled) is limited to a documented allowlist of safe methods.
4. **Stable surface is contract-stable.** See [STABILITY.md](STABILITY.md). Changing config keys, audit JSON fields, signed field set, metric names, or JSON-RPC error codes requires a MAJOR version bump and at least one MINOR release of deprecation warning.

## PR expectations

- One concern per PR. If a change touches storage AND adds a new policy feature, split it.
- Use conventional commit prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `build:`. Scope optional: `fix(storage): ...`.
- Update [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` when the change is user-visible. Internal refactors and tests don't require a changelog entry. If unsure, ask in the PR.
- Update tests in the same PR as the code change. A PR that adds a feature without tests will be sent back.
- Include a short test plan in the PR description if you changed runtime behavior. Reference the manual smoke test if the change affects something the test suite doesn't cover.
- Sign commits if you can (`git config commit.gpgsign true`). Not required.

## Security

Do not open public issues or PRs for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the private reporting channel (GitHub Security Advisories preferred).

When reviewing or generating code, watch for:

- Path traversal in any code that reads/writes files based on input
- Unbounded buffers when reading from JSON-RPC streams or HTTP bodies
- `tls.InsecureSkipVerify` outside of explicitly opt-in code paths
- Secrets logged at any log level
- Concurrent map writes (Go panics)
- Send-on-closed-channel races

These are real bug classes that have shipped (or been caught pre-ship) on this project before. See `internal/audit/storage/sqlite.go` and `async.go` for examples of concurrency fixes.

## When in doubt

- Check open issues labeled `good first issue` for scoped work
- Read [CONTRIBUTING.md](CONTRIBUTING.md) for the human-oriented contributor guide
- For design questions on an existing surface, open a [Discussion](https://github.com/P4ST4S/mcp-audit/discussions) rather than a feature issue
- For changes that might affect the public API surface (anything in [STABILITY.md](STABILITY.md)), flag this explicitly in the PR description

## What not to do

- Don't add files outside the scope of the PR (e.g., `.DS_Store`, editor configs, scratch directories)
- Don't introduce platform-specific code without explicit cross-platform handling. `mcp-audit` ships for linux, darwin, windows
- Don't widen the public surface without checking [STABILITY.md](STABILITY.md) first
- Don't write tests that depend on the current wall clock, OS locale, or timezone unless the test explicitly exercises that behavior
- Don't paste generated code without reading and understanding it. The PR is yours, regardless of how it was authored
