# WitnessOS Verifier

[![OpenSSF Best Practices - Baseline 1](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fwww.bestpractices.dev%2Fprojects%2F14138.json&query=badge_percentage_baseline_1&label=OpenSSF%20Baseline%201&suffix=%25&color=success)](https://www.bestpractices.dev/projects/14138) [![OpenSSF Best Practices - Baseline 2](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fwww.bestpractices.dev%2Fprojects%2F14138.json&query=badge_percentage_baseline_2&label=OpenSSF%20Baseline%202&suffix=%25&color=success)](https://www.bestpractices.dev/projects/14138) [![OpenSSF Best Practices - Baseline 3](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fwww.bestpractices.dev%2Fprojects%2F14138.json&query=badge_percentage_baseline_3&label=OpenSSF%20Baseline%203&suffix=%25&color=success)](https://www.bestpractices.dev/projects/14138)

> **E4 verification implemented with explicit external trust.** Real RFC 3161 signatures and independent custodian receipts are verified. The existing fixtures still lack production retention receipts; Stripe also has a root mismatch. See [E4-BUNDLE-FORMAT.md](E4-BUNDLE-FORMAT.md) and [E4-IMPLEMENTATION-REPORT.md](E4-IMPLEMENTATION-REPORT.md).

Standalone verifier for WitnessOS evidence bundles. It checks event and manifest Ed25519 signatures, canonical event chains, sequence bounds, event membership, and binding to the signed batch root. Bundled keys prove consistency with those keys; authenticate their identity independently.

| Grade | Required evidence |
|---|---|
| E0 | No events loaded (grade-derivation API) |
| E1 | Events loaded |
| E2 | E1 plus valid event/manifest signatures, chain, sequence and signed batch binding |
| E3 | E2 plus a signed event recording provider acknowledgement |
| E4 | E3 plus bound inclusion proof, authenticated timestamp and authenticated WORM retention evidence |

E3 records the signer's claim about a provider response; it does not independently authenticate a provider or query a live service. E4 requires operator-provisioned TSA trust roots and an independently signed storage-custodian receipt over the timestamped snapshot. A matching local WORM checksum is not immutability evidence.

The CLI returns exit 1 when supplied evidence fails or cannot be verified. A lower grade may describe checks that passed; it does not override an invalid bundle result.

## Installation

```bash
pip install witnessos-verifier
```

Or from source:

```bash
git clone https://github.com/narko4u/witnessos-verifier.git
cd witnessos-verifier
pip install -e ".[dev]"
```

Requires Python 3.12+ and OpenSSL 3 on PATH for timestamp authentication.

## Usage

```bash
# Verify using independently provisioned trust
witnessos-verifier verify ./path/to/evidence-bundle/ \
  --trust-policy /path/to/operator-policy.json --tsa-url https://freetsa.org/tsr

# Verify in Alpha mode - grades capped at E3
witnessos-verifier verify --alpha ./path/to/evidence-bundle/

# Get version
witnessos-verifier --version
```

## Example fixtures

Fixtures are unchanged from the upstream review except `e4-stripe-refund`, whose
events/root/proof/timestamp were regenerated on 2026-09-08 so canonical events
reproduce the signed Merkle root (previously the root binding failed, capping the
lane at E1).

- `e4-gmail-approved-send`: signatures and signed event-root binding pass; the real FreeTSA signature passes with operator trust, but an independent retention receipt is missing. E3, invalid bundle, exit 1.
- `e4-stripe-refund`: canonical events now reproduce the signed Merkle root (fixture regenerated 2026-09-08); event signatures and the real FreeTSA signature pass with operator trust, but an independent retention receipt is missing. E3, invalid bundle, exit 1.

No fixture has been demonstrated to be valid E4 without an independent custodian receipt. Both fixtures grade E4 only when the operator trust policy names a retention authority whose signed receipt is present (see E4-IMPLEMENTATION-REPORT.md). Do not present the test custodian as real WORM custody.

## Development

```bash
# Clone
git clone https://github.com/narko4u/witnessos-verifier.git
cd witnessos-verifier

# Install dev dependencies
pip install -e ".[dev]"

# Run tests (all offline)
pytest tests/ -v

# Verify the fixture
witnessos-verifier verify fixtures/e4-gmail-approved-send/
```

## Architecture

```
src/witnessos_verifier/
├── __init__.py          # Package version
├── cli.py               # Click CLI
├── verifier.py          # Main orchestrator
├── events.py            # Event loading + canonical hashing
├── signatures.py        # Ed25519 signature verification
├── key_registry.py      # Public key management
├── case_chain.py        # Case hash chain verification
├── ledger.py            # Global ledger verification
├── merkle.py            # CT Merkle tree proofs
├── manifest.py          # Signed batch manifest verification
├── timestamp.py         # RFC 3161 timestamp verification
├── worm.py              # WORM evidence integrity
├── der.py               # Minimal ASN.1 DER parser (stdlib only)
└── grades.py            # E1-E4 evidence grade derivation
```

## Timestamp and retention trust

CMS signatures, ESS signer binding, certificate paths at genTime, timestamping
purpose/EKU, digest/policy/nonce constraints and the timestamp trust window are
verified. STANDARD does not check revocation. STRICT/revocation-required policies
fail closed until authenticated CRL/OCSP support exists. Signed retention receipts
prove what an independently trusted custodian attested; the offline verifier does
not query live storage. See the exact [bundle recipe](E4-BUNDLE-FORMAT.md).

## Dependencies

- **pynacl** - Ed25519 signature verification
- **click** - CLI
- **asn1crypto** - ASN.1/CMS structure parsing
- **cryptography** - X.509 certificate parsing
- **OpenSSL 3 executable** - RFC 3161 signature and certificate-path verification
- Optional S3 adapters require boto3; they are not used for E4 verification

No gateway, no credentials, no network. **Verification happens on your machine.**

### Dependency management

The project follows a deliberate, minimal dependency policy:

1. **Selection** - new dependencies are avoided unless a standard-library
   alternative does not exist. Cryptographic and ASN.1 dependencies support real signature and certificate verification; see `pyproject.toml`.
2. **Obtaining** - dependencies are declared in `pyproject.toml` and pinned
   through the `uv.lock` lockfile, so every build uses a reproducible set of
   package versions.
3. **Tracking** - dependencies are monitored three ways:
   - **SCA**: every push/PR runs [OSV-Scanner](https://google.github.io/osv-scanner/)
     in the `security` workflow to detect known vulnerabilities in the lockfile.
   - **SBOM**: every release ships a CycloneDX SBOM (`sbom.cdx.json`) listing
     the exact dependency set of the released artifact.
   - **Integrity**: every release asset ships with a Sigstore signature and a
     `SHA256SUMS` checksum manifest (see [Verifying releases](#verifying-releases)).

## Verifying releases

### 1. Integrity (checksums)

Each release ships a `SHA256SUMS` file listing the hashes of every release
asset. To verify that a downloaded asset matches the published release:

```sh
sha256sum -c SHA256SUMS
```

This checks the integrity of the wheel, source tarball, and SBOM against the
hashes generated at release time. The `SHA256SUMS` file itself is attached
to the GitHub release (see the [Releases](https://github.com/narko4u/witnessos-verifier/releases) page), so integrity can be checked without trusting the download mirror.

### 2. Authenticity (Sigstore/cosign signatures)

Every release asset is signed **keylessly** with [Sigstore](https://www.sigstore.dev/)
at build time by the `Release` GitHub Actions workflow. Each asset is shipped
with a `.sig` signature and a `.pem` signing certificate. To verify the
signature of an asset:

```sh
# install cosign: https://docs.sigstore.dev/cosign/installation/
cosign verify-blob \
  --certificate-identity "https://github.com/narko4u/witnessos-verifier/.github/workflows/release.yml@refs/tags/v*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature witnessos_verifier-0.2.0-py3-none-any.whl.sig \
  --certificate witnessos_verifier-0.2.0-py3-none-any.whl.pem \
  witnessos_verifier-0.2.0-py3-none-any.whl
```

### 3. Release author identity

Releases are authored by the **Empire Labs Pty Ltd** maintainer team and
built automatically by the `Release` GitHub Actions workflow in the
`narko4u/witnessos-verifier` repository (identity
`https://github.com/narko4u/witnessos-verifier/.github/workflows/release.yml@refs/tags/v*`,
issuer `https://token.actions.githubusercontent.com`). The Sigstore
certificate embedded in each `.pem` file binds every asset to exactly this
workflow and tag - if the certificate identity in step 2 does not match,
the asset was not produced by this project's release process.

### 4. Software Bill of Materials (SBOM)

Each release ships a CycloneDX SBOM (`sbom.cdx.json`) generated from the
built artifacts by the `Release` workflow. The SBOM lists every runtime and
build dependency so consumers can inventory the supply chain of the wheel
and source tarball. Verify it with the same checksum and signature
verification steps above.

### 5. VEX and threat assessment

The repository also publishes a [VEX](VEX.md) document accounting for known
vulnerabilities that do not affect the project, and a
[threat assessment](THREAT-ASSESSMENT.md) covering the attack surface and
mitigations for each release.

## License

Apache 2.0 - see [LICENSE](LICENSE)

## Related

- [WitnessOS™ Spec](https://github.com/narko4u/witnessos) - the protocol specification
- [Contact Empire Labs](mailto:contact@empirelabs.com.au)

---

**Built by Empire Labs Pty Ltd.** WitnessOS is a trademark of Empire Labs.


---

<sub>Part of the [WitnessOS launch family](https://github.com/narko4u/witnessos): [witnessos-alpha](https://github.com/narko4u/witnessos-alpha) · [witnessos-compliance](https://github.com/narko4u/witnessos-compliance) · [eu-ai-act-compliance-grade](https://github.com/narko4u/eu-ai-act-compliance-grade) · [witnessos-rogue-agent-audit](https://github.com/narko4u/witnessos-rogue-agent-audit) · [witnessos-agent-asset-registry](https://github.com/narko4u/witnessos-agent-asset-registry) · [witnessos-verifier](https://github.com/narko4u/witnessos-verifier) · [agent-interaction-specs](https://github.com/narko4u/agent-interaction-specs) · [aci-spec](https://github.com/narko4u/aci-spec) · [aip-spec](https://github.com/narko4u/aip-spec) · [ajson](https://github.com/narko4u/ajson) - [Empire Labs Pty Ltd](https://www.empirelabs.com.au)</sub>