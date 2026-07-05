# Security Policy

Kanonarion is a supply-chain analysis tool, so we take the integrity of this
project - and your trust in its output - seriously.

## Supported Versions

Kanonarion is pre-`v1.0`. Only the current release line, **`v0.1`**, receives
security fixes; every earlier or pre-release version is unsupported. Pin a
`v0.1.x` tag and upgrade promptly.

| Version | Supported |
|-----------------------|-----------|
| `v0.1.x` | ✅ |
| anything older than `v0.1` | ❌ |

## Reporting a Vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/eitanity/kanonarion/security/advisories/new)
(Security → Advisories → "Report a vulnerability"), or email
**security@eitanity.com**.

Please include:

- a description of the issue and its impact,
- the version or commit affected,
- reproduction steps or a proof of concept,
- any suggested remediation.

## What to Expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity triage within 10 business days.
- Coordinated disclosure: we will agree on a disclosure timeline with you and
  credit you in the advisory unless you prefer to remain anonymous.

## Release Integrity

Released artifacts are signed and published with a self-SBOM. Verify signatures
and the SBOM before trusting a downloaded binary; instructions accompany each
release.
