# Contributing

Thank you for your interest in witnessos-verifier!

## Scope

This repository is the **standalone open-source verifier**. It contains:

- Verification logic for WitnessOS evidence bundles
- Cryptographic proof checking (Ed25519, Merkle trees, RFC 3161 timestamps)
- A command-line interface
- Offline test suite with sanitised fixtures

It does **not** contain gateway code, credential brokering, policy engines, or connector logic. Those are proprietary components of the WitnessOS platform.

## Development setup

```bash
git clone https://github.com/narko4u/witnessos-verifier.git
cd witnessos-verifier
pip install -e ".[dev]"
```

## Running tests

All tests are offline - no network required:

```bash
pytest tests/ -v
```

The project's testing policy (when tests run, what they must cover, and the
requirement that major changes add or update automated tests) is documented
in [TESTING.md](TESTING.md).

## Code style

- Type hints on all public functions
- Docstrings on all public modules and functions
- 100% offline compatibility for all verification logic
- No external cryptographic libraries beyond PyNaCl for Ed25519

## Pull requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure tests pass: `pytest tests/ -v`
5. Verify the fixture: `witnessos-verifier verify fixtures/e4-gmail-approved-send/`
6. Submit a PR against `main`

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Questions

Open a [GitHub Discussion](https://github.com/narko4u/witnessos-verifier/discussions) or email [contact@empirelabs.com.au](mailto:contact@empirelabs.com.au).
