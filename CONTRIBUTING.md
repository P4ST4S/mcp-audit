# Contributing to mcp-audit

Contributions are welcome. This is an experimental project — keep changes 
focused and the scope small.

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
- `go test ./...` passes
- `gofmt` has been run on changed Go files
- Changes are scoped to one concern per PR

## Good first issues

Check issues labeled [`good first issue`](https://github.com/P4ST4S/mcp-audit/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) 
for approachable starting points.

## Guiding principles

- **Zero accidental message drop** — the proxy must not drop or modify JSON-RPC
  messages because auditing or interception failed. If inspection fails,
  forward as-is and log the error separately. Intentional policy enforcement,
  such as rate limiting, must return a proper JSON-RPC error.
- **Minimal dependencies** — prefer stdlib over new packages.
- **Errors with context** — wrap errors: `fmt.Errorf("component: action: %w", err)`
- **Thread safety** — all storage writes must be safe for concurrent use.

## Opening an issue

For bugs, include Go version, OS, transport mode (stdio/http), and the 
minimal config to reproduce. For features, check the existing issues first.

## Security issues

Please do not open public issues for security vulnerabilities. Report them
privately to the maintainer.

## License

By contributing you agree your changes are licensed under Apache-2.0.
