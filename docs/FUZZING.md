# Fuzzing

Security-sensitive parsers and canonicalization code include checked-in seed
corpora. The seeds run as ordinary regression tests with `go test ./...`.

Run active fuzzing from the repository root with one target at a time:

```bash
go test -run '^$' -fuzz '^FuzzInspectRequest$' -fuzztime 30s ./internal/mcp
go test -run '^$' -fuzz '^FuzzDecodeMessages$' -fuzztime 30s ./internal/mcp
go test -run '^$' -fuzz '^FuzzVerifyIntegrity$' -fuzztime 30s ./internal/audit/integrity
go test -run '^$' -fuzz '^FuzzJSONRPCDecodeAndErrorResponse$' -fuzztime 30s ./internal/proxy
go test -run '^$' -fuzz '^FuzzHTTPAccessListNormalization$' -fuzztime 30s ./internal/proxy
go test -run '^$' -fuzz '^FuzzSSEStream$' -fuzztime 30s ./internal/proxy
```

Long-running campaigns should preserve any generated corpus entries that expose
a crash or invariant violation. Add the minimized input to the matching
`f.Add` seed list so every normal test run prevents the regression.
