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

For issues in the WitnessOS gateway or platform, see the [main WitnessOS repository](https://github.com/narko4u/witnessos).

## Design principles

The verifier is designed to be:

1. **Offline-first** — no network calls during verification
2. **Minimal dependencies** — only PyNaCl for Ed25519, everything else stdlib
3. **No trust required** — verify don't trust, every check is cryptographic
4. **Deterministic** — same input always produces the same result

## Dependencies

| Dependency | Version | Purpose |
|-----------|---------|---------|
| PyNaCl | >=1.5.0 | Ed25519 signatures |
| Python stdlib | 3.10+ | Everything else |

We deliberately avoid large cryptographic frameworks (cryptography, pyOpenSSL) to keep the audit surface minimal.

## Responsible disclosure history

None yet — you could be the first.

[![Security](https://img.shields.io/badge/Security-Policy-blue)](./SECURITY.md)
