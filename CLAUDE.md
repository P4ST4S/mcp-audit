@AGENTS.md

## Claude Code specific

The instructions above apply to all agents. Below are notes specific to Claude Code sessions on this repository.

### Working directory

Run Claude Code from the repo root. The build, test, and lint commands in `AGENTS.md` assume this.

### Verification reflexes the maintainer values

When you make a non-trivial code change, the maintainer expects you to verify it concretely before claiming it's done:

- Run `go build ./...` after touching Go code
- Run `go test -race ./...` for any change that touches `internal/`
- For changes to `cmd/mcp-audit/` or `internal/proxy/`, run a manual smoke test against the built binary with `demo/config.yaml` before reporting completion
- For test additions, run `go test -shuffle=on -count=3 ./pkg-under-test/...` to confirm the test doesn't depend on hidden state

If you skip verification, say so explicitly ("I haven't run the smoke test because X") rather than implying it passed.

### Plan mode for surface changes

Use plan mode (`EnterPlanMode`) before changes that touch:

- The stable surface listed in [STABILITY.md](STABILITY.md): config keys, CLI flags, audit JSON schema, the signed field set, Prometheus metric names, OTLP `mcp_audit.*` attributes, dashboard API endpoints, or JSON-RPC error codes
- Concurrency-sensitive code in `internal/audit/storage/` (the SQLite mutex and the async-store closeMu lock both fix real prior bugs; touching them without a plan is risky)
- Anything in `cmd/mcp-audit/main.go` that affects startup ordering or signal handling

For pure additions in `internal/` packages (new tests, new feature flag wired through the existing pattern), plan mode is optional.

### When asked to draft text the maintainer will post publicly

Some output here is destined for GitHub comments, Discord messages, or LinkedIn posts. House style:

- Never use the em-dash character. Use commas, periods, or split the sentence.
- Never use "we" when speaking on the maintainer's behalf — he is solo on this project.
- Never say "Welcome to open source" or similar paternalistic greetings to contributors. Treat them as peers.
- Don't post "thanks for the thanks." Once is enough.
- If the message adds no new information, suggest an emoji reaction (👍 🎉 👀) instead of a comment.

### Memory and prior context

Auto memory for this repository lives at `~/.claude/projects/-Users-antoinerospars-projects-mcp-audit/memory/`. It contains active PR tracking, contributor patterns, and house style notes. Check it when the maintainer references prior work without re-explaining context.
