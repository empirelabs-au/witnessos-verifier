# Security

## Reporting vulnerabilities

**Do not open a public issue.** Email [contact@empirelabs.com.au](mailto:contact@empirelabs.com.au) with:

- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Any proposed fix (optional)

We aim to acknowledge reports within 48 hours and provide a timeline for resolution within 5 business days.

## Scope

Security issues in **this repository only**:

- Cryptographic verification bypasses
- ASN.1/DER parser vulnerabilities
- Merkle proof validation weaknesses
- Timestamp token parsing issues

For issues in other Empire Labs projects, report them in the affected project's own repository.

## Design principles

The verifier is designed to be:

1. **Offline-first** - no network calls during verification
2. **Minimal dependencies** - only PyNaCl for Ed25519, everything else stdlib
3. **No trust required** - verify don't trust, every check is cryptographic
4. **Deterministic** - same input always produces the same result

## Dependencies

| Dependency | Version | Purpose |
|-----------|---------|---------|
| PyNaCl | >=1.5.0 | Ed25519 signatures |
| Python stdlib | 3.10+ | Everything else |

We deliberately avoid large cryptographic frameworks (cryptography, pyOpenSSL) to keep the audit surface minimal.

## Supported versions

Security fixes are applied to the latest release. Older releases are patched on a best-effort basis for critical issues only.

## End of life

A release is considered end of life once it has been superseded by a newer release. Superseded releases no longer receive security updates except critical-only best-effort patches.

## Secrets and credentials

- Secrets (API keys, tokens, passwords, private keys) must never be committed to this repository. CI and local development use environment-provided credentials only.
- Repository secrets are stored in GitHub encrypted secrets and are scoped to the workflows that need them.
- If a secret is exposed, rotate it immediately, remove it from repository history, and report the exposure to contact@empirelabs.com.au.

## Dependency and static-analysis remediation policy

- Software Composition Analysis (SCA): known-vulnerable dependencies are remediated before any release. Critical and high severity findings are remediated within 30 days; medium within 90 days.
- Static Application Security Testing (SAST): findings are triaged on the same severity thresholds (critical/high within 30 days, medium within 90 days). Findings that cannot be fixed are documented with a justification.
- No release is cut while critical or high severity SCA or SAST findings are unresolved.

## Responsible disclosure history

None yet - you could be the first.

[![Security](https://img.shields.io/badge/Security-Policy-blue)](./SECURITY.md)
