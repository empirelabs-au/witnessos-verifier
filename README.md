# witnessos-verifier

> **Alpha Status:** This verifier is in Alpha. Evidence grades are capped at E3 when running with `--alpha` flag. E4 evidence is verified but not asserted. See [WitnessOS SPEC](https://github.com/narko4u/witnessos) for protocol details.

Standalone open-source verifier for [WitnessOS™](https://github.com/narko4u/witnessos) evidence bundles.

**Independently verify AI action receipts - no gateway, no credentials, no network required.**

## What it does

You receive a WitnessOS evidence bundle (a directory of JSON files, a Merkle proof, a signed manifest, an RFC 3161 timestamp token, and WORM store metadata). You run:

```
witnessos-verifier verify ./evidence-bundle/
```

And you get:

```
Grade:  E4 - Externally anchored
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     PASS
  WORM:    PASS
```

Every check runs **offline** - no network access is required during verification. Trust is evaluated against the evidence bundle's public keys and configured timestamp-authority trust policy.

## What it verifies

| Check | What it proves |
|-------|---------------|
| E1: Events loaded | The bundle contains valid events |
| E2: Case hash chain | Each event links to the previous one (tamper-evident sequence) |
| E2: Ledger sequence | Events are part of a monotonic global ledger |
| E2: Manifest signature | The batch was signed by an authorized WitnessOS key |
| E3: Provider acknowledged | An external provider confirmed the action |
| E4: RFC 3161 timestamp | A trusted timestamp authority anchored the batch in real time |
| E4: WORM evidence copy | The evidence hasn't been modified since storage |

**E4 is the highest grade** - externally anchored, independently verifiable evidence.

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

Requires Python 3.10+.

## Usage

```bash
# Verify an evidence bundle (production - E4 available)
witnessos-verifier verify ./path/to/evidence-bundle/

# Verify in Alpha mode - grades capped at E3
witnessos-verifier verify --alpha ./path/to/evidence-bundle/

# Get version
witnessos-verifier --version
```

## Example fixtures

### Gmail send - `fixtures/e4-gmail-approved-send/`

A sanitised, self-contained demonstration bundle representing a Gmail send action that was:

1. **Requested** by an AI agent
2. **Checked** against communication policy
3. **Permitted** with a scoped one-time permit
4. **Credential-brokered** via OAuth2
5. **Provider acknowledgement recorded from the Gmail API**
6. **Signed** by the WitnessOS batch key
7. **Externally timestamped** (RFC 3161 standard)
8. **Stored** in a WORM evidence vault

All values are sanitised - no real email addresses, message IDs, or API keys.

```bash
witnessos-verifier verify fixtures/e4-gmail-approved-send/
```

### Stripe refund - `fixtures/e4-stripe-refund/`

A sanitised, self-contained demonstration bundle representing a Stripe test-mode refund that was:

1. **Requested** by an AI agent
2. **Checked** against communication policy
3. **Permitted** with a scoped one-time permit bound to exact refund target, amount, and reason
4. **Credential-brokered** via Stripe test-mode key
5. **Provider acknowledgement** recorded from the Stripe API
6. **Provider confirmation** via webhook (HMAC-SHA256 verified)
7. **Signed** by the WitnessOS batch key
8. **Externally timestamped** (RFC 3161 standard)
9. **Stored** in a WORM evidence vault

Both fixtures prove evidence integrity, signatures, anchoring, and grade derivation. They do **not** query any live service. Verification is fully offline.

```bash
witnessos-verifier verify fixtures/e4-stripe-refund/
```

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

## What RFC 3161 verification checks

The timestamp verifier does not merely parse DER. It validates:

- **Token signature** - the TimeStampToken's SignedData signature must verify against the TSA's certificate
- **Data imprint** - the `messageImprint` hash must match the batch's Merkle tree root
- **TSA certificate identity** - the signing certificate must chain to a trusted root CA
- **Key usage** - the certificate must assert `id-kp-timeStamping` Extended Key Usage
- **Nonce/freshness** - if a nonce was supplied, the response must echo it
- **Policy** - the TSA's asserted policy OID must match the configured trust policy
- **Certificate status** - the TSA certificate must not be expired and must pass revocation checks (CRL or OCSP, configurable)
- **Algorithm acceptance** - only approved hash and signature algorithms are accepted

These checks can only pass against a configured trust anchor policy. The demonstration
fixture ships with a relaxed policy suitable for testing; production deployments
configure their own TSA providers and root CAs.

## Dependencies

- **pynacl** - Ed25519 signature verification (sole external dependency)
- Everything else is Python stdlib

No gateway, no credentials, no network. **Verification happens on your machine.**

## License

Apache 2.0 - see [LICENSE](LICENSE)

## Related

- [WitnessOS™ Spec](https://github.com/narko4u/witnessos) - the protocol specification
- [Contact Empire Labs](mailto:contact@empirelabs.com.au)

---

**Built by Empire Labs Pty Ltd.** WitnessOS is a trademark of Empire Labs.


---

<sub>Part of the [WitnessOS launch family](https://github.com/narko4u/witnessos): [witnessos-alpha](https://github.com/narko4u/witnessos-alpha) · [witnessos-compliance](https://github.com/narko4u/witnessos-compliance) · [eu-ai-act-compliance-grade](https://github.com/narko4u/eu-ai-act-compliance-grade) · [witnessos-rogue-agent-audit](https://github.com/narko4u/witnessos-rogue-agent-audit) · [witnessos-agent-asset-registry](https://github.com/narko4u/witnessos-agent-asset-registry) · [witnessos-verifier](https://github.com/narko4u/witnessos-verifier) · [agent-interaction-specs](https://github.com/narko4u/agent-interaction-specs) · [aci-spec](https://github.com/narko4u/aci-spec) · [aip-spec](https://github.com/narko4u/aip-spec) · [ajson](https://github.com/narko4u/ajson) - [Empire Labs Pty Ltd](https://www.empirelabs.com.au)</sub>