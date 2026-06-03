# Contributing to mcp-audit

Contributions are welcome. Keep changes focused and the scope small. Stability guarantees are documented in [STABILITY.md](STABILITY.md).

## Getting started

```bash
git clone https://github.com/P4ST4S/mcp-audit
cd mcp-audit
go build ./...
go test ./...
```

## Before opening a PR

- `go build ./...` passes
- `go vet ./...` passes
- `go test -race ./...` passes
- `gofmt` has been run on changed Go files
- Changes are scoped to one concern per PR

## Pull request conventions

These conventions are recommended, not strictly enforced by CI. The PR template at [`.github/pull_request_template.md`](.github/pull_request_template.md) prompts for the right sections automatically.

### Scope

One PR addresses one concern. If a change touches storage and adds a new policy feature, split it into two PRs. A clean diff is easier to review, easier to revert if something breaks, and easier to credit if part of it lands.

If the issue you're addressing has multiple parts (see [#4117 on `modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers/issues/4117) as an example), open a comment on the issue first describing how you intend to split the work. This avoids two contributors stepping on each other.

### Branch names

Suggested format: `type/short-description-issue` (the issue number is optional).

```
feat/policy-engine-15
fix/storage-race-42
docs/cursor-example-19
refactor/storage-tests
chore/release-1.0.0
```

Use the same `type` you'd use in your commit message. The hyphen-separated description should be enough that someone scanning your fork's branch list can tell what you were working on.

### Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/). The type is required, the scope is optional but encouraged when it disambiguates.

| Type | Use for |
| --- | --- |
| `feat` | New user-visible feature (added config key, new flag, new metric, etc.) |
| `fix` | Bug fix (also use for security fixes; mention CVE if any) |
| `docs` | Documentation only (README, CHANGELOG, this file, etc.) |
| `test` | Test additions or improvements with no production code change |
| `refactor` | Internal restructuring with no behavior change |
| `chore` | Release prep, dependency bumps, repo housekeeping |
| `build` | Build pipeline, CI, GoReleaser, Dockerfile changes |
| `perf` | Performance improvement with no behavior change |

Examples from the project history:

```
fix(memory): default persistence path to user data directory
feat: add HTTP upstream retry metrics and logging
test(storage): add unit tests for storage backends
chore: release v1.0.0
```

The commit message body is encouraged for non-trivial changes: explain the why, link the issue, and call out any risk. The CHANGELOG entry is a separate concern.

### CHANGELOG entries

Update [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` when your change is user-visible. Internal refactors, tests, and CI changes do not require a changelog entry.

Categories:
- `### Added` for new features
- `### Changed` for changes in existing behavior
- `### Fixed` for bug fixes
- `### Deprecated` for soon-to-be-removed features (must announce at least one MINOR release ahead, per [STABILITY.md](STABILITY.md))
- `### Removed` for removed features (requires MAJOR bump)
- `### Security` for vulnerabilities

If you're not sure whether your change needs an entry, ask in the PR. Easier to add one than to debate later.

### Stability surface

Anything in the stable surface (config keys, CLI flags, audit JSON schema, signed field set, Prometheus metric names, OTLP `mcp_audit.*` attributes, dashboard API endpoints, JSON-RPC error codes) is contract-stable per [STABILITY.md](STABILITY.md).

If your PR touches any of these:

- Call it out in the PR description under "Stability impact"
- Additive changes (new fields, new flags, new metrics) are MINOR-compatible
- Removals, renames, or behavior changes need a deprecation cycle and eventually a MAJOR version bump

When in doubt, flag it in the PR description and the reviewer will help triage.

### Merge strategy

PRs are merged with a **merge commit**, not squashed. This preserves your individual commits in the history, which makes it easier to credit step-by-step work and to bisect later if something breaks.

Consequently: keep your commits clean before requesting review. If you ended up with a `wip`, `fix typo`, `oops`, and then `actually fix it` sequence, rebase them into meaningful commits before pushing the final round.

### Review etiquette

- Tag the maintainer (`@P4ST4S`) once when the PR is ready for review. Avoid re-pinging within 7 days; review backlog moves slowly on solo-maintained projects.
- If a reviewer requests changes, address each point or explain why you disagree. "Why" is welcome — silent dismissal isn't.
- If your PR depends on another open PR, say so in the description and link it. PR 2 of a sequence shouldn't be opened before PR 1 is reviewed.
- Allow edits from maintainers (the checkbox on the PR creation form). Lets the reviewer fix a typo or rebase without ping-pong.

## Good first issues

Check issues labeled [`good first issue`](https://github.com/P4ST4S/mcp-audit/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) 
for approachable starting points.

## Project layout

- `cmd/mcp-audit/` - CLI entry point and config loading
- `internal/proxy/` - stdio and HTTP MCP proxies
- `internal/audit/` - entry types, signing, JSONL and SQLite storage backends
- `internal/policy/` - synchronous allow/deny policy engine
- `internal/middleware/` - rate limiting and PII redaction
- `internal/metrics/` - Prometheus metrics recorder and endpoint
- `internal/otel/` - OTLP/HTTP JSON trace exporter
- `internal/dashboard/` - read-only HTTP dashboard and JSON API

## Guiding principles

- **Zero accidental message drop** - the proxy must not drop or modify JSON-RPC
  messages because auditing or interception failed. If inspection fails,
  forward as-is and log the error separately. Intentional policy enforcement,
  such as rate limiting, must return a proper JSON-RPC error.
- **Minimal dependencies** - prefer stdlib over new packages.
- **Errors with context** - wrap errors: `fmt.Errorf("component: action: %w", err)`
- **Thread safety** - all storage writes must be safe for concurrent use.

## Opening an issue

For bugs, include Go version, OS, transport mode (stdio/http), and the minimal config to reproduce. For features, check the existing issues first.

For open-ended questions, design conversations, or "would it make sense to..." ideas, prefer [Discussions](https://github.com/P4ST4S/mcp-audit/discussions) over Issues.

## Security issues

Please do not open public issues for security vulnerabilities. Follow the private reporting process in [SECURITY.md](SECURITY.md).

## License

By contributing you agree your changes are licensed under Apache-2.0.
