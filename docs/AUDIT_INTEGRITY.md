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
tool_name
params
result
error
duration_ms
client_id
server_id
```

The legacy `signature` and the `integrity` metadata are not part of the signed
payload. Optional fields preserve their JSON presence semantics: an absent
field and an explicit JSON `null` are distinct inputs.

Redaction and default field population happen before both signatures are
computed. The durable entry is therefore exactly what Integrity v2 verifies.

## Key identification

`audit.signing.key_id` defaults to `default` and is copied into every Integrity
v2 object. It identifies the verification key without exposing key material and
allows a verifier to select among rotated keys in a future release.

The signing secret remains configured through `AUDIT_SECRET` or the existing
`audit.secret` setting. The environment variable takes precedence.
