# Changelog

## 0.2.0 (2026-06-28)

### Added

- **Stripe E4 demonstration fixture**: 7-event evidence bundle for a Stripe test-mode refund workflow
- **Generator script**: `scripts/generate_stripe_demo_fixture.py` - reproducible E4 bundle generator
- **README**: Clear statement of what offline verification proves vs. what it does not

### Changed

- **Version bump**: 0.1.0 → 0.2.0

## 0.1.0 (2026-06-27)

Initial public release of the WitnessOS standalone open-source verifier.

### Features

- **CLI**: `witnessos-verifier verify ./bundle/` command
- **Event loading**: Parse canonical JSON events with hash computation
- **Case hash chain**: Verify prev_hash links across events
- **Ledger verification**: Validate monotonic sequence numbers and head consistency
- **Merkle proofs**: CT Merkle tree inclusion and consistency proof verification
- **Manifest verification**: Ed25519 signature verification on signed batch manifests
- **Timestamp verification**: RFC 3161 timestamp token parsing and imprint verification
- **WORM integrity**: Evidence bundle hash comparison against stored records
- **Grade derivation**: E1-E4 evidence grading
- **Offline fixture**: Sanitised E4-grade evidence bundle for testing
- **Zero network requirement**: All verification runs entirely offline

### Dependencies

- Python 3.10+
- PyNaCl >= 1.5.0 (sole external dependency)

### Known limitations

- Certificate chain validation in timestamps is not yet implemented (imprint verification only)
- Only Ed25519 signatures are supported
- No WASM/JavaScript build for browser verification (planned)

---

[Unreleased]: https://github.com/narko4u/witnessos-verifier/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/narko4u/witnessos-verifier/releases/tag/v0.1.0
