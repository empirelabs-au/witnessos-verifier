# Adversarial launch review

Verdict: **not-ready**.

Scope: `empirelabs-au/witnessos-verifier`, main `a5a30fa2e1d92964663e2c5686c4f445948af2e1`, PR #10 head `ad056f866201e9274178bec683d720768af42269`. Fix branch: `attack/bundle-integrity`, based on main and incorporating PR #10's grading/vocabulary fixes. Do not merge both blindly; this PR supersedes its code changes.

Direct HTTPS clone failed: `fatal: could not read Username for 'https://github.com': No such device or address`. Instead the authenticated GitHub connector retrieved all 68 files at the pinned main SHA. Every Git blob SHA, the full tree SHA, and the reconstructed shallow signed commit SHA matched upstream. This is an exact shallow Git snapshot, not a successful native clone. No credentials were read or changed. Connector identity: narko4u. Only this repository was accessed/modified.

## Findings

Locations below refer to main/PR #10 source before containment unless stated otherwise.

| Location | Severity | Finding / disposition |
|---|---|---|
| `src/witnessos_verifier/grades.py:126` (main) | blocker | E4 bypassed E3, including alpha returning E3 without ack. PR #10 fixes this gate and dot/underscore vocabulary; retained. |
| `src/witnessos_verifier/verifier.py:139-154,213` | blocker | Only manifest signature checked; no event signatures, event-ID/sequence/case membership or recomputed root binding. Alter final payload/signature or truncate final event, recompute editable WORM checksum: still valid E4 on PR #10. Fixed with explicit checks. |
| `src/witnessos_verifier/verifier.py:18,213`; `merkle.py:59` | blocker | Inclusion proof never invoked by orchestrator. Delete or replace proof with `{}`, recompute checksum: valid E4. Fixed proof/event/root/index/size binding. |
| `src/witnessos_verifier/timestamp.py:206-210,274`; `cert_chain.py:324-334` | blocker | SignerInfos read but never verified. CMS helper returned True as a stub. Corrupt token's final byte: valid E4. Now fails closed; **real CMS signature and trusted-path integration remain unimplemented**. This containment intentionally refuses even potentially authentic tokens; it is not a production E4 implementation. |
| `src/witnessos_verifier/worm.py:75-93` | blocker | Unsigned, co-located checksums are editable by the bundle producer and prove no independent retention. All attacks rehash them without any signing key. E4 now requires separate authenticated retention evidence that this release cannot provide. |
| `src/witnessos_verifier/verifier.py:152-155,239` | major | Malformed manifest converted to warning; bundle returned valid=True/E1. Now error/exit 1. Missing keys/manifest and verification exceptions also fail closed. |
| `fixtures/e4-stripe-refund/merkle_proof.json:2`; `batch_manifest.json:15` | blocker | Stored root `8f8fb08f6759c22ec81355f92ae4b2b42137f8eff23ad8028525cef29be48b9b`; repository's canonical-event tree produces `24805fe897e9efcc6d863b5ecd67dcf0fae6881ed8bbcad04dacd33fd1a7a8a9`. First proof leaf also mismatches. Both fixture sets' Ed25519 event signatures do verify. Producer leaf/tree convention needs reconciliation; no fixture modified or special-cased. |
| `src/witnessos_verifier/trust_policy.py:204-210` | major | CRL/OCSP configuration and installed library were reported CHECKED without fetching/verifying anything. Now FAIL_CLOSED when revocation required; implementation remains unavailable. |
| `src/witnessos_verifier/merkle.py:76-133,136-151` | major | Consistency proof uses simplified fallback; tree builder duplicates odd leaves while calling itself CT. These are not a complete CT proof implementation. Existing tree convention retained for compatibility; production protocol reconciliation remains open. |
| `src/witnessos_verifier/cert_chain.py:148-229,269-283` | major | Certificate validation is incomplete (CA constraints, intermediate validity and general path building; unknown OID defaults to SHA-256). Not wired into authenticated token verification; external anchoring stays disabled pending proper implementation. |
| `src/witnessos_verifier/worm_adapters.py:269-306` | major | S3 adapter unconditionally reports immutable, tolerates absent retention and labels ETag as SHA-256. Not used by offline verify; remains an unvalidated adapter, not an E4 capability. No AWS operations performed. |
| `README.md:20-45,154-170` | major | Claimed signatures/trusted TSA/nonce/revocation/retention that execution did not establish. Main README/CLI now describe actual limits; other assurance docs explicitly flag historical claims. |
| `src/witnessos_verifier/der.py:6` | minor | Private gateway repository name in public-facing module docstring. PR #10 removal retained. No secret values found in reviewed source; this is not a credential audit. |

## Fix and test scope

Containment verifies both event-signature schemas, exact batch membership/root binding and inclusion proof, enforces the cumulative ladder through explicit positive results, rejects malformed evidence, rejects bundle symlinks, and prevents parser/checksum results becoming E4. Local WORM exclusion is now relative to the bundle so a parent folder named `worm` cannot suppress every file.

Existing E4 fixture tests were corrected to assert the discovered limits rather than preserve false-positive expectations. Fixtures and keys are byte-for-byte unchanged. All mutations in attack tests use disposable copies. New tests include independent signature failure detection, both event vocabularies and positive/negative grade derivation. The positive E4 unit cases use result doubles; they are **not evidence of working end-to-end E4 authentication**.

Release gates still open: implement and validate CMS/trust/nonce/revocation, authenticate retention, reconcile Stripe root encoding and CT proof convention, harden optional certificate/storage APIs. This PR makes failure honest; it does not make an E4 public launch ready.

## Real command output

Initial `uv run pytest` could not spawn pytest; installed the declared dev extra with `uv sync --extra dev`, then ran the exact requested command. Outputs below are captured verbatim except the explicitly omitted repetitive attack assertion tracebacks. CLI exits: main and PR #10 both bundles 0; fixed branch both bundles 1. Main suite exit 0; PR #10 suite exit 0; seven adversarial assertions on PR #10 exit 1; fixed suite exit 0.

### main: uv run pytest

```text
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-9.1.1, pluggy-1.6.0 -- /workspace/scratch/e23923bfde48/witnessos-verifier/.venv/bin/python3
cachedir: .pytest_cache
rootdir: /workspace/scratch/e23923bfde48/witnessos-verifier
configfile: pyproject.toml
testpaths: tests
plugins: cov-7.1.0
collecting ... collected 33 items

tests/test_e2e.py::TestE2EVerification::test_full_verification_passes PASSED [  3%]
tests/test_e2e.py::TestE2EVerification::test_all_requirements_in_result PASSED [  6%]
tests/test_e2e.py::TestE2EVerification::test_no_requirements_missing PASSED [  9%]
tests/test_e2e.py::TestCLIVerify::test_cli_verify_output PASSED          [ 12%]
tests/test_e2e.py::TestEmptyBundle::test_empty_bundle_graceful PASSED    [ 15%]
tests/test_events.py::TestEventLoading::test_loads_all_seven_events PASSED [ 18%]
tests/test_events.py::TestEventLoading::test_events_have_sequential_ids PASSED [ 21%]
tests/test_events.py::TestEventLoading::test_events_have_sequential_seqs PASSED [ 24%]
tests/test_events.py::TestEventLoading::test_events_have_valid_prev_hash_chain PASSED [ 27%]
tests/test_events.py::TestEventLoading::test_canonical_bytes_are_valid_json PASSED [ 30%]
tests/test_events.py::TestEventLoading::test_all_events_signed PASSED    [ 33%]
tests/test_events.py::TestBogusInput::test_empty_dir PASSED              [ 36%]
tests/test_events.py::TestBogusInput::test_invalid_json PASSED           [ 39%]
tests/test_events.py::TestBogusInput::test_missing_fields PASSED         [ 42%]
tests/test_fuzz.py::TestDERInputValidation::test_empty_input PASSED      [ 45%]
tests/test_fuzz.py::TestDERInputValidation::test_garbage_input PASSED    [ 48%]
tests/test_fuzz.py::TestDERInputValidation::test_truncated_sequence PASSED [ 51%]
tests/test_fuzz.py::TestDERInputValidation::test_strict_mode_trailing_garbage PASSED [ 54%]
tests/test_fuzz.py::TestDERInputValidation::test_non_minimal_length_encoding_rejected PASSED [ 57%]
tests/test_fuzz.py::TestDERInputValidation::test_oversized_input PASSED  [ 60%]
tests/test_fuzz.py::TestTSTInfoValidation::test_missing_fields_reported PASSED [ 63%]
tests/test_fuzz.py::TestTSTInfoValidation::test_tst_info_parse_error_message PASSED [ 66%]
tests/test_fuzz.py::TestOIDValidation::test_rejects_unknown_oid PASSED   [ 69%]
tests/test_fuzz.py::TestOIDValidation::test_accepts_known_oid PASSED     [ 72%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_policy_allows_all PASSED [ 75%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_standard_policy_blocks_unlisted_tsa PASSED [ 78%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_policy_allows_all_hash_algorithms PASSED [ 81%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_no_cert_chain_required PASSED [ 84%]
tests/test_signatures.py::TestDetachedSignature::test_valid_signature PASSED [ 87%]
tests/test_signatures.py::TestDetachedSignature::test_bad_signature PASSED [ 90%]
tests/test_signatures.py::TestDetachedSignature::test_wrong_message PASSED [ 93%]
tests/test_signatures.py::TestDetachedSignature::test_wrong_key PASSED   [ 96%]
tests/test_signatures.py::TestEventSignaturesViaVerifier::test_all_events_pass_verification PASSED [100%]

============================== 33 passed in 0.22s ==============================
```

### main: CLI Gmail

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/fixtures/e4-gmail-approved-send
Grade:  E4
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     PASS
  Trust:   DEMO → not_required
  WORM:    PASS

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E3: Provider acknowledged
  ✓ E4: RFC 3161 timestamp valid
  ✓ E4: WORM evidence copy valid
```

### main: CLI Stripe

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/fixtures/e4-stripe-refund
Grade:  E4
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     PASS
  Trust:   DEMO → not_required
  WORM:    PASS

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E4: RFC 3161 timestamp valid
  ✓ E4: WORM evidence copy valid
Requirements not met:
  ✗ E3: No provider acknowledgement found
```

### PR #10: uv run pytest

```text
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-9.1.1, pluggy-1.6.0 -- /workspace/scratch/e23923bfde48/witnessos-verifier/.venv/bin/python3
cachedir: .pytest_cache
rootdir: /workspace/scratch/e23923bfde48/witnessos-verifier
configfile: pyproject.toml
testpaths: tests
plugins: cov-7.1.0
collecting ... collected 38 items

tests/test_e2e.py::TestE2EVerification::test_full_verification_passes PASSED [  2%]
tests/test_e2e.py::TestE2EVerification::test_all_requirements_in_result PASSED [  5%]
tests/test_e2e.py::TestE2EVerification::test_no_requirements_missing PASSED [  7%]
tests/test_e2e.py::TestCLIVerify::test_cli_verify_output PASSED          [ 10%]
tests/test_e2e.py::TestEmptyBundle::test_empty_bundle_graceful PASSED    [ 13%]
tests/test_events.py::TestEventLoading::test_loads_all_seven_events PASSED [ 15%]
tests/test_events.py::TestEventLoading::test_events_have_sequential_ids PASSED [ 18%]
tests/test_events.py::TestEventLoading::test_events_have_sequential_seqs PASSED [ 21%]
tests/test_events.py::TestEventLoading::test_events_have_valid_prev_hash_chain PASSED [ 23%]
tests/test_events.py::TestEventLoading::test_canonical_bytes_are_valid_json PASSED [ 26%]
tests/test_events.py::TestEventLoading::test_all_events_signed PASSED    [ 28%]
tests/test_events.py::TestBogusInput::test_empty_dir PASSED              [ 31%]
tests/test_events.py::TestBogusInput::test_invalid_json PASSED           [ 34%]
tests/test_events.py::TestBogusInput::test_missing_fields PASSED         [ 36%]
tests/test_fuzz.py::TestDERInputValidation::test_empty_input PASSED      [ 39%]
tests/test_fuzz.py::TestDERInputValidation::test_garbage_input PASSED    [ 42%]
tests/test_fuzz.py::TestDERInputValidation::test_truncated_sequence PASSED [ 44%]
tests/test_fuzz.py::TestDERInputValidation::test_strict_mode_trailing_garbage PASSED [ 47%]
tests/test_fuzz.py::TestDERInputValidation::test_non_minimal_length_encoding_rejected PASSED [ 50%]
tests/test_fuzz.py::TestDERInputValidation::test_oversized_input PASSED  [ 52%]
tests/test_fuzz.py::TestTSTInfoValidation::test_missing_fields_reported PASSED [ 55%]
tests/test_fuzz.py::TestTSTInfoValidation::test_tst_info_parse_error_message PASSED [ 57%]
tests/test_fuzz.py::TestOIDValidation::test_rejects_unknown_oid PASSED   [ 60%]
tests/test_fuzz.py::TestOIDValidation::test_accepts_known_oid PASSED     [ 63%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_policy_allows_all PASSED [ 65%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_standard_policy_blocks_unlisted_tsa PASSED [ 68%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_policy_allows_all_hash_algorithms PASSED [ 71%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_no_cert_chain_required PASSED [ 73%]
tests/test_grade_integrity.py::TestE3VocabularyBothForms::test_dot_vocabulary_acknowledged PASSED [ 76%]
tests/test_grade_integrity.py::TestE3VocabularyBothForms::test_dot_vocabulary_confirmed PASSED [ 78%]
tests/test_grade_integrity.py::TestE4RequiresE3::test_no_ack_tsa_present_caps_below_e4 PASSED [ 81%]
tests/test_grade_integrity.py::TestE4RequiresE3::test_full_e4_requires_ack PASSED [ 84%]
tests/test_grade_integrity.py::TestE4RequiresE3::test_alpha_caps_e4_to_e3_only_with_ack PASSED [ 86%]
tests/test_signatures.py::TestDetachedSignature::test_valid_signature PASSED [ 89%]
tests/test_signatures.py::TestDetachedSignature::test_bad_signature PASSED [ 92%]
tests/test_signatures.py::TestDetachedSignature::test_wrong_message PASSED [ 94%]
tests/test_signatures.py::TestDetachedSignature::test_wrong_key PASSED   [ 97%]
tests/test_signatures.py::TestEventSignaturesViaVerifier::test_all_events_pass_verification PASSED [100%]

============================== 38 passed in 0.13s ==============================
```

### PR #10: CLI Gmail

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/fixtures/e4-gmail-approved-send
Grade:  E4
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     PASS
  Trust:   DEMO → not_required
  WORM:    PASS

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E3: Provider acknowledged
  ✓ E4: RFC 3161 timestamp valid
  ✓ E4: WORM evidence copy valid
```

### PR #10: CLI Stripe

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/fixtures/e4-stripe-refund
Grade:  E4
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     PASS
  Trust:   DEMO → not_required
  WORM:    PASS

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E3: Provider acknowledged
  ✓ E4: RFC 3161 timestamp valid
  ✓ E4: WORM evidence copy valid
```

### PR #10: uv run pytest tests/test_adversarial_bundle.py -s --basetemp=.git/attack-tmp

```text
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-9.1.1, pluggy-1.6.0 -- /workspace/scratch/e23923bfde48/witnessos-verifier/.venv/bin/python3
cachedir: .pytest_cache
rootdir: /workspace/scratch/e23923bfde48/witnessos-verifier
configfile: pyproject.toml
plugins: cov-7.1.0
collecting ... collected 7 items

tests/test_adversarial_bundle.py::test_reject_attacker_bundle[last_payload] last_payload: valid=True, grade=E4
FAILED
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[last_signature] last_signature: valid=True, grade=E4
FAILED
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[delete_proof] delete_proof: valid=True, grade=E4
FAILED
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[fake_proof] fake_proof: valid=True, grade=E4
FAILED
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[timestamp_signature] timestamp_signature: valid=True, grade=E4
FAILED
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[truncate_events] truncate_events: valid=True, grade=E4
FAILED
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[malformed_manifest] malformed_manifest: valid=True, grade=E1
FAILED

[Assertion tracebacks omitted; verbatim attack results and test summary retained.]
=========================== short test summary info ============================
FAILED tests/test_adversarial_bundle.py::test_reject_attacker_bundle[last_payload]
FAILED tests/test_adversarial_bundle.py::test_reject_attacker_bundle[last_signature]
FAILED tests/test_adversarial_bundle.py::test_reject_attacker_bundle[delete_proof]
FAILED tests/test_adversarial_bundle.py::test_reject_attacker_bundle[fake_proof]
FAILED tests/test_adversarial_bundle.py::test_reject_attacker_bundle[timestamp_signature]
FAILED tests/test_adversarial_bundle.py::test_reject_attacker_bundle[truncate_events]
FAILED tests/test_adversarial_bundle.py::test_reject_attacker_bundle[malformed_manifest]
============================== 7 failed in 0.08s ===============================
```

### fix: uv run pytest

```text
============================= test session starts ==============================
platform linux -- Python 3.12.13, pytest-9.1.1, pluggy-1.6.0 -- /workspace/scratch/e23923bfde48/witnessos-verifier/.venv/bin/python3
cachedir: .pytest_cache
rootdir: /workspace/scratch/e23923bfde48/witnessos-verifier
configfile: pyproject.toml
testpaths: tests
plugins: cov-7.1.0
collecting ... collected 57 items

tests/test_adversarial_bundle.py::test_reject_attacker_bundle[last_payload] PASSED [  1%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[last_signature] PASSED [  3%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[delete_proof] PASSED [  5%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[fake_proof] PASSED [  7%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[timestamp_signature] PASSED [  8%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[truncate_events] PASSED [ 10%]
tests/test_adversarial_bundle.py::test_reject_attacker_bundle[malformed_manifest] PASSED [ 12%]
tests/test_adversarial_bundle.py::test_real_event_signatures_both_vocabularies[e4-gmail-approved-send] PASSED [ 14%]
tests/test_adversarial_bundle.py::test_real_event_signatures_both_vocabularies[e4-stripe-refund] PASSED [ 15%]
tests/test_adversarial_bundle.py::test_signature_attack_is_detected_independently PASSED [ 17%]
tests/test_adversarial_bundle.py::test_all_ack_vocabulary[provider.acknowledged] PASSED [ 19%]
tests/test_adversarial_bundle.py::test_all_ack_vocabulary[provider.confirmed] PASSED [ 21%]
tests/test_adversarial_bundle.py::test_all_ack_vocabulary[provider_acknowledged] PASSED [ 22%]
tests/test_adversarial_bundle.py::test_all_ack_vocabulary[provider_confirmed] PASSED [ 24%]
tests/test_adversarial_bundle.py::test_cumulative_ladder[events_loaded-E0] PASSED [ 26%]
tests/test_adversarial_bundle.py::test_cumulative_ladder[event_signatures_valid-E1] PASSED [ 28%]
tests/test_adversarial_bundle.py::test_cumulative_ladder[batch_binding_valid-E1] PASSED [ 29%]
tests/test_adversarial_bundle.py::test_cumulative_ladder[has_provider_ack-E2] PASSED [ 31%]
tests/test_adversarial_bundle.py::test_parsing_and_checksums_do_not_make_e4 PASSED [ 33%]
tests/test_e2e.py::TestE2EVerification::test_fixture_reports_unverified_anchor PASSED [ 35%]
tests/test_e2e.py::TestE2EVerification::test_all_requirements_in_result PASSED [ 36%]
tests/test_e2e.py::TestE2EVerification::test_external_requirements_explicitly_missing PASSED [ 38%]
tests/test_e2e.py::TestCLIVerify::test_cli_verify_output PASSED          [ 40%]
tests/test_e2e.py::TestEmptyBundle::test_empty_bundle_graceful PASSED    [ 42%]
tests/test_events.py::TestEventLoading::test_loads_all_seven_events PASSED [ 43%]
tests/test_events.py::TestEventLoading::test_events_have_sequential_ids PASSED [ 45%]
tests/test_events.py::TestEventLoading::test_events_have_sequential_seqs PASSED [ 47%]
tests/test_events.py::TestEventLoading::test_events_have_valid_prev_hash_chain PASSED [ 49%]
tests/test_events.py::TestEventLoading::test_canonical_bytes_are_valid_json PASSED [ 50%]
tests/test_events.py::TestEventLoading::test_all_events_signed PASSED    [ 52%]
tests/test_events.py::TestBogusInput::test_empty_dir PASSED              [ 54%]
tests/test_events.py::TestBogusInput::test_invalid_json PASSED           [ 56%]
tests/test_events.py::TestBogusInput::test_missing_fields PASSED         [ 57%]
tests/test_fuzz.py::TestDERInputValidation::test_empty_input PASSED      [ 59%]
tests/test_fuzz.py::TestDERInputValidation::test_garbage_input PASSED    [ 61%]
tests/test_fuzz.py::TestDERInputValidation::test_truncated_sequence PASSED [ 63%]
tests/test_fuzz.py::TestDERInputValidation::test_strict_mode_trailing_garbage PASSED [ 64%]
tests/test_fuzz.py::TestDERInputValidation::test_non_minimal_length_encoding_rejected PASSED [ 66%]
tests/test_fuzz.py::TestDERInputValidation::test_oversized_input PASSED  [ 68%]
tests/test_fuzz.py::TestTSTInfoValidation::test_missing_fields_reported PASSED [ 70%]
tests/test_fuzz.py::TestTSTInfoValidation::test_tst_info_parse_error_message PASSED [ 71%]
tests/test_fuzz.py::TestOIDValidation::test_rejects_unknown_oid PASSED   [ 73%]
tests/test_fuzz.py::TestOIDValidation::test_accepts_known_oid PASSED     [ 75%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_policy_allows_all PASSED [ 77%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_standard_policy_blocks_unlisted_tsa PASSED [ 78%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_policy_allows_all_hash_algorithms PASSED [ 80%]
tests/test_fuzz.py::TestTrustPolicyValidation::test_demo_no_cert_chain_required PASSED [ 82%]
tests/test_grade_integrity.py::TestE3VocabularyBothForms::test_dot_vocabulary_acknowledged PASSED [ 84%]
tests/test_grade_integrity.py::TestE3VocabularyBothForms::test_dot_vocabulary_confirmed PASSED [ 85%]
tests/test_grade_integrity.py::TestE4RequiresE3::test_no_ack_tsa_present_caps_below_e4 PASSED [ 87%]
tests/test_grade_integrity.py::TestE4RequiresE3::test_full_e4_requires_ack PASSED [ 89%]
tests/test_grade_integrity.py::TestE4RequiresE3::test_alpha_caps_e4_to_e3_only_with_ack PASSED [ 91%]
tests/test_signatures.py::TestDetachedSignature::test_valid_signature PASSED [ 92%]
tests/test_signatures.py::TestDetachedSignature::test_bad_signature PASSED [ 94%]
tests/test_signatures.py::TestDetachedSignature::test_wrong_message PASSED [ 96%]
tests/test_signatures.py::TestDetachedSignature::test_wrong_key PASSED   [ 98%]
tests/test_signatures.py::TestEventSignaturesViaVerifier::test_all_events_pass_verification PASSED [100%]

============================== 57 passed in 0.21s ==============================
```

### fix: uv run witnessos-verifier verify fixtures/e4-gmail-approved-send

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/fixtures/e4-gmail-approved-send
Grade:  E3
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     FAIL
  Trust:   DEMO → not_required
  WORM checksum: PASS (retention unverified)

Errors:
  ✗ TSA signature and trusted certificate path are not verified; external anchoring unavailable

Warnings (2):
  ⚠ Bundled public keys establish signature consistency, not signer identity; authenticate keys independently.
  ⚠ Local WORM checksums do not prove remote retention or immutability.

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E2: Event signatures valid
  ✓ E2: Events bound to signed batch
  ✓ E3: Provider acknowledged
  ✓ E4: Merkle inclusion proof valid
Requirements not met:
  ✗ E4: RFC 3161 timestamp invalid or missing
  ✗ E4: Authenticated WORM retention evidence invalid or missing
```

### fix: uv run witnessos-verifier verify fixtures/e4-stripe-refund

```text
Bundle: /workspace/scratch/e23923bfde48/witnessos-verifier/fixtures/e4-stripe-refund
Grade:  E1
Events: 7
  Chain:   PASS (6/7 links)
  Ledger:  PASS
  Manifest: PASS
  TSA:     FAIL
  Trust:   DEMO → not_required
  WORM checksum: PASS (retention unverified)

Errors:
  ✗ Loaded events do not match signed Merkle root
  ✗ Merkle proof: proof is not bound to event and signed root
  ✗ TSA signature and trusted certificate path are not verified; external anchoring unavailable

Warnings (2):
  ⚠ Bundled public keys establish signature consistency, not signer identity; authenticate keys independently.
  ⚠ Local WORM checksums do not prove remote retention or immutability.

Requirements met:
  ✓ E1: Events loaded
  ✓ E2: Case hash chain valid
  ✓ E2: Ledger sequence valid
  ✓ E2: Manifest signature valid
  ✓ E2: Event signatures valid
Requirements not met:
  ✗ E2: Events bound to signed batch
```
