# E4 Evidence Bundle — Stripe Test-Mode Refund

**Externally timestamped demonstration evidence bundle based on a Stripe test-mode workflow.**

- 7 events: action.requested → anchor.completed
- Ed25519 signatures on all events
- CT Merkle tree + inclusion proof
- Signed batch manifest
- RFC 3161 timestamp (FreeTSA)
- WORM evidence copy

**This is a demonstration fixture.** No real Stripe keys, customer data,
or production signing material is included. All identifiers (case_id,
refund_id, charge_id, payment_intent_id, keys) are purpose-generated
demo values.

**What offline verification proves:**
- Event and manifest integrity
- Signature validity
- Anchoring
- Evidence-grade derivation

**What it does NOT prove:**
- Independent live querying of Stripe

```bash
witnessos-verifier verify fixtures/e4-stripe-refund/
```
Expected: **E4 — Externally anchored**

Generated: 2026-06-28T05:37:30Z
