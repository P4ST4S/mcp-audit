# Stability Policy

`mcp-audit` follows [Semantic Versioning 2.0.0](https://semver.org/). This document spells out what that means in practice for users of the project: what is guaranteed to stay stable, what may evolve between releases, and how breaking changes are announced.

## Versioning

Releases are tagged as `vMAJOR.MINOR.PATCH`.

- **MAJOR** (e.g. `v2.0.0`) — breaking changes to the stable surface (see below).
- **MINOR** (e.g. `v1.1.0`) — additive changes only. New configuration keys, new CLI flags, new metrics, new examples. Existing behavior preserved.
- **PATCH** (e.g. `v1.0.1`) — bug fixes, security fixes, documentation updates. No behavior change other than fixing what was broken.

A breaking change in any of the surfaces listed under [Stable surface](#stable-surface) requires a MAJOR bump.

## Stable surface

The following surfaces are covered by the stability policy starting at `v1.0.0`:

### Configuration (`config.yaml`)

- Existing keys keep their meaning and accepted values.
- New keys are additive and have safe defaults.
- Removing or renaming a key requires a MAJOR bump and a deprecation period (see [Deprecation](#deprecation)).

### CLI flags

- Existing flags keep their meaning and accepted values.
- New flags are additive.
- The `--version` output format is documented and stable: `mcp-audit <version> (commit <sha>, built <iso8601>)`.

### Audit entry JSON schema

The fields recorded for each audit entry (`id`, `timestamp`, `direction`, `transport`, `method`, `request_id`, `tool_name`, `params`, `result`, `error`, `duration_ms`, `client_id`, `server_id`, `signature`) keep their names and types. New fields may be added in MINOR releases. Existing fields are not removed or renamed without a MAJOR bump.

The signature is computed over `id + timestamp + method + tool_name + params`. Changing the signed field set requires a MAJOR bump because it invalidates existing signatures.

### Prometheus metrics

Metric names and label sets are stable. The `mcp_audit_*` prefix is reserved. New metrics are additive. A metric is never removed or renamed in a MINOR release.

### OTLP export attributes

MCP and GenAI semantic convention attributes follow the upstream OpenTelemetry semantic conventions as they evolve. Because the MCP semconv is itself marked **Development** upstream, renames at that layer are tracked and reflected in MINOR releases, with a note in the changelog when this happens. Project-scoped attributes under the `mcp_audit.*` prefix are stable.

### Dashboard HTTP API

The read-only API endpoints (`GET /api/entries`, `GET /api/stats`) keep their query parameters and response shape. New parameters may be added in MINOR releases.

### Exit codes and JSON-RPC error codes

The proxy-emitted JSON-RPC error codes (`-32029` rate-limited, `-32030` policy denied) are stable.

## Not part of the stable surface

The following are explicitly **not** covered by the stability policy and may change in any release, including MINOR:

- The internal Go package layout (`internal/...`). The project is an application, not a library. Code under `internal/` is not importable by third parties and may be refactored at any time.
- Log message formats and levels emitted by the proxy.
- The HTML structure of the dashboard page (the API endpoints under `/api/*` are stable; the HTML is not).
- The format of intermediate or debug files written for development purposes.
- Behavior under unsupported configurations (e.g. fields explicitly outside the documented schema).

## Deprecation

When a stable surface item is going to be removed or renamed in a future MAJOR release, the following process applies:

1. The item is marked **deprecated** in the changelog of a MINOR release.
2. At runtime, `mcp-audit` logs a warning when the deprecated item is used, with a pointer to the replacement.
3. The deprecation is documented in the release notes and in the relevant section of the README.
4. The earliest MAJOR release that removes the item is at least **one MINOR release later** than the deprecation announcement.

In practice this means: if `v1.3.0` deprecates a config key, the earliest release that may remove it is `v2.0.0` shipped after `v1.4.0` (or later) has had time to land. Users have at least one MINOR release window to migrate.

## Supported versions

Security fixes are backported to **the latest MINOR release of the current MAJOR**.

- During `v1.x`, only `v1.<latest>.*` receives security fixes.
- When `v2.0.0` ships, `v1.x` enters a 90-day grace period during which critical security fixes are still backported to `v1.<latest>.*`.
- After the 90-day grace period, `v1.x` is no longer maintained.

Functional bug fixes are landed on the current MINOR only, not backported.

This policy reflects the project being maintained by a single person with limited bandwidth. If maintenance capacity grows, the support window may be extended; it will not be narrowed without a MAJOR bump.

## Reporting a stability concern

If you believe a release has broken something covered by this policy without a MAJOR bump, please open an issue with the label `stability-regression`. Stability regressions are treated as bugs and are fixed in a PATCH release.

For security-related stability issues, follow the process in [SECURITY.md](SECURITY.md) instead.
