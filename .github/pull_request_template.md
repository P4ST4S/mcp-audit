<!--
Thanks for contributing to mcp-audit. Sections below are suggested — leave a
section out if it doesn't apply to your PR. Verbose templates discourage
contributions, so the only "rule" is: tell the reviewer what they need to know.
-->

## Summary

<!-- One or two sentences. What does this change, and why? -->

## Context

<!-- Optional. Link the issue if one exists, or explain the trigger. -->

Closes #

## Approach

<!-- Optional. Skip for trivial changes. For non-trivial changes, briefly
explain the design choice and any alternative you considered. -->

## Test plan

<!--
Required if your change touches runtime behavior. List the commands you ran
and what they verified. Examples:

- `go test -race ./internal/audit/storage/...` — all tests pass, no race
- Manual smoke: built binary, ran with `demo/config.yaml`, confirmed
  the new policy rule blocks `delete_file` with code -32030
- N/A — docs-only PR
-->

## Stability impact

<!--
Required if you touched any of the surfaces listed in STABILITY.md:
config keys, CLI flags, audit JSON schema, signed field set, Prometheus
metric names, OTLP `mcp_audit.*` attributes, dashboard API endpoints, or
JSON-RPC error codes.

For all other changes, you can write "None" or omit this section.
-->

## Notes for reviewer

<!-- Optional. Anything you want the reviewer to focus on, edge cases you're
unsure about, or follow-ups that are intentionally out of scope. -->
