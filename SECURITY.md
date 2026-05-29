# Security Policy

`mcp-audit` is a security and observability proxy for MCP traffic. Please report suspected vulnerabilities privately so they can be investigated and fixed before public disclosure.

## Reporting a Vulnerability

Preferred channel:

- Open a private GitHub Security Advisory: https://github.com/P4ST4S/mcp-audit/security/advisories/new

Fallback channel:

- Email the maintainer at antoine.rospars@epitech.eu

Please include:

- A clear description of the issue and affected component.
- Reproduction steps or a minimal proof of concept.
- Impact assessment, including whether audit integrity, policy enforcement, redaction, storage, dashboard exposure, or proxy forwarding is affected.
- Affected version or commit SHA.
- Any logs, configuration, or payload samples needed to reproduce the issue. Do not include real secrets, credentials, or private user data.

## Scope

Security reports are in scope when they affect `mcp-audit` itself, including:

- Proxy behavior for stdio or HTTP MCP traffic.
- Audit log integrity, signing, storage, or tamper-evidence behavior.
- PII redaction behavior.
- Policy enforcement and rate limiting.
- Dashboard or metrics exposure.
- OpenTelemetry export behavior when it could leak sensitive data or weaken audit guarantees.
- Configuration handling that could expose secrets or bypass expected security controls.

Out of scope:

- Vulnerabilities in upstream MCP servers wrapped by `mcp-audit`.
- Vulnerabilities in MCP clients such as Claude Desktop, Cursor, or other clients.
- Vulnerabilities in third-party collectors, databases, dashboards, or infrastructure connected to `mcp-audit`.
- Denial-of-service reports that require unrealistic local access or intentionally hostile local configuration.
- Reports about missing bug bounty rewards. This project does not currently run a paid bounty program.

## Response Expectations

- Acknowledgement: within 5 business days.
- Initial triage: within 10 business days when enough reproduction detail is provided.
- Fix timeline: depends on severity and complexity. Critical issues that affect audit integrity, policy bypass, sensitive data disclosure, or remote dashboard exposure will be prioritized.

If more information is needed, the maintainer may ask follow-up questions through the private advisory thread or by email.

## Disclosure Policy

`mcp-audit` follows coordinated disclosure:

- Do not open a public GitHub issue for a suspected vulnerability.
- Do not publish exploit details until a fix is available and users have had reasonable time to upgrade.
- The default embargo target is 90 days from acknowledgement.
- Shorter or longer embargoes may be agreed depending on severity, exploitability, and fix complexity.
- Once fixed, the project may publish a GitHub Security Advisory, release notes, and upgrade guidance.

## Supported Versions

Before v1.0.0, security fixes target the latest released version only. Users should upgrade to the latest release before reporting or validating a security issue.
