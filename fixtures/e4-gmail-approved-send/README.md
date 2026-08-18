# E4 Evidence Bundle - Gmail Approved Send

**Sanitised fixture for witnessos-verifier.**

- 7 events: action_requested → case_closed
- Ed25519 signatures on all events
- CT Merkle tree + inclusion proof
- Signed batch manifest
- RFC 3161 timestamp (FreeTSA)
- WORM evidence copy

```bash
witnessos-verifier verify fixtures/e4-gmail-approved-send/
```
Expected: **E4 - Externally anchored**
