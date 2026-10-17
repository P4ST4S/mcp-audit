# Audit integrity formats

`mcp-audit` v1.2 adds Integrity v2 without changing the legacy `signature`
field. When signing is enabled and a secret is configured, new entries contain
both formats so existing consumers can migrate independently.

## Legacy v1 signature

The `signature` field remains an HMAC-SHA256 over the direct concatenation of:

```text
id + timestamp + method + tool_name + params
```

Its field set and encoding are unchanged. This format is retained for backward
compatibility and must not be interpreted as authenticating the complete entry.

## Integrity v2

Integrity v2 is stored as an additive object:

```json
{
  "integrity": {
    "version": 2,
    "algorithm": "hmac-sha256",
    "key_id": "default",
    "signature": "0123abcd..."
  }
}
```

The signature is the lowercase hexadecimal HMAC-SHA256 of an
[RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
payload. JCS removes insignificant whitespace, recursively sorts object keys,
and applies deterministic JSON primitive serialization. Invalid I-JSON, such
as duplicate object keys, is rejected instead of being signed ambiguously.

The payload protects these fields:

```text
id
timestamp
audit_operation_id
outcome
direction
transport
method
request_id
mcp_name
tool_name
params
result
error
duration_ms
client_id
server_id
principal
policy
```

The legacy `signature` and the `integrity` metadata are not part of the signed
payload. Optional fields preserve their JSON presence semantics: an absent
field and an explicit JSON `null` are distinct inputs.

Redaction and default field population happen before both signatures are
computed. The durable entry is therefore exactly what Integrity v2 verifies.

Individual signatures authenticate the protected content of each present entry.
They do not establish that every expected entry is present, or its position in
the stream. Default verification accepts valid legacy signatures for historical
compatibility; `verify --require-integrity-v2` requires v2 on every entry and
rejects an empty artifact.

## Ordered snapshot checkpoint v1 (v1.3)

`mcp-audit checkpoint <artifact> --output <new-file>` verifies a nonempty v2
snapshot and writes a JSON object with `version` (`1`), `algorithm`
(`hmac-sha256/sha256`), `key_id`, `format` (`jsonl` or `sqlite`), `records`,
`digest`, and `signature`. Existing output files are never overwritten. The
signing secret and key ID are supplied as for `verify`.

The lowercase hexadecimal SHA-256 digest covers each record, in order, as its
8-byte unsigned big-endian canonical byte length followed by RFC 8785 JCS
bytes. JSONL covers complete JSON objects, including extra fields, and ignores
blank lines and insignificant whitespace. SQLite covers the defined audit
fields decoded from rows ordered by `rowid`, rather than database pages, schema,
or unrelated columns. Checkpoints are specific to their storage format.

The lowercase hexadecimal HMAC-SHA256 signature covers the ASCII domain
`mcp-audit/checkpoint/v1` followed by a newline, then the JCS representation of
all checkpoint fields except `signature`. Existing entry signatures and their
protected field sets are unchanged.

`verify --checkpoint FILE` validates that signature, then compares the complete
ordered snapshot digest and record count. It also requires every entry to pass
v2 verification. Missing, inserted, duplicated, reordered or changed records
fail verification relative to that expected checkpoint.

Create checkpoints from closed or quiescent snapshots, then retain the expected
checkpoint/version in a separately controlled location. An attacker who can
replace both inputs with an older valid pair can roll back evidence undetected;
a holder of the HMAC secret can forge both. This is a whole-artifact checkpoint,
not a Merkle inclusion proof or an automatic checkpoint of a live/rotated stream.
It cannot prove that an operation which never reached storage occurred.

## Key identification

`audit.signing.key_id` defaults to `default` and is copied into every Integrity
v2 object. It identifies the verification key without exposing key material and
allows a verifier to select among rotated keys in a future release.

The signing secret is configured through `MCP_AUDIT_SIGNING_SECRET` or the
existing `audit.secret` setting. The legacy `AUDIT_SECRET` name remains
supported. The preferred environment variable takes precedence over both.
