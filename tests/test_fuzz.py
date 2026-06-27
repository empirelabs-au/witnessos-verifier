"""Fuzzing and malformed-input rejection tests for parser hardening.

Tests that the DER parser + timestamp verifier properly reject:
  - Empty input
  - Truncated DER
  - Garbage data
  - Oversized input
  - Invalid OIDs
  - Strict-mode trailing garbage
"""

import pytest
from pathlib import Path


class TestDERInputValidation:
    def test_empty_input(self):
        from witnessos_verifier.der import validate_der_input
        issues = validate_der_input(b"")
        assert len(issues) > 0
        assert any("Empty" in i for i in issues)

    def test_garbage_input(self):
        from witnessos_verifier.der import validate_der_input
        issues = validate_der_input(b"\x00\x01\x02\xFF\xFE")
        assert len(issues) > 0
        assert any("SEQUENCE" in i for i in issues)

    def test_truncated_sequence(self):
        from witnessos_verifier.der import validate_der_input
        # SEQUENCE tag + length claiming 100 bytes, but only 4 bytes provided
        issues = validate_der_input(b"\x30\x64\x00\x00")
        assert len(issues) > 0
        assert any("exceeds data" in i.lower() for i in issues)

    def test_strict_mode_trailing_garbage(self):
        from witnessos_verifier.der import validate_der_input
        # Valid empty SEQUENCE + garbage
        data = b"\x30\x00" + b"\xDE\xAD\xBE\xEF"
        issues = validate_der_input(data, strict=True)
        assert len(issues) > 0
        assert any("trailing" in i.lower() for i in issues)

    def test_non_minimal_length_encoding_rejected(self):
        from witnessos_verifier.der import DerError
        # Short-form 0x05 would encode length 5, but 0x81 0x05 is long form
        # with value 5 — non-minimal DER for a value under 128.
        # Our _decode_length checks for this.
        with pytest.raises(DerError, match="Non-minimal|not supported"):
            from witnessos_verifier.der import _decode_length
            # Value 5 encoded with long form (non-minimal: should be 0x05)
            _decode_length(b"\x81\x05" + b"\x00" * 5, 0)

    def test_oversized_input(self):
        from witnessos_verifier.der import validate_der_input, MAX_DER_SIZE
        data = b"\x30" + b"\x00" * (MAX_DER_SIZE + 100)
        issues = validate_der_input(data)
        assert len(issues) > 0
        assert any("max size" in i.lower() for i in issues)


class TestTSTInfoValidation:
    def test_missing_fields_reported(self):
        from witnessos_verifier.der import validate_tst_info_fields
        # TSTInfo with only version — missing policy, messageImprint, etc.
        minimal = bytes([0x30, 0x03, 0x02, 0x01, 0x01])  # SEQUENCE { INTEGER 1 }
        issues = validate_tst_info_fields(minimal)
        # Parsing should fail — either with "Missing" or "error"
        assert len(issues) > 0, f"Expected issues, got none"
        assert any(
            "Missing" in i or "error" in i.lower() for i in issues
        ), f"Issues: {issues}"

    def test_tst_info_parse_error_message(self):
        """Minimal TSTInfo causes DER parse error when missing required fields."""
        from witnessos_verifier.der import validate_tst_info_fields
        # Only version byte — parsing will fail trying to read OID for policy
        minimal = bytes([0x30, 0x03, 0x02, 0x01, 0x01])
        issues = validate_tst_info_fields(minimal)
        assert len(issues) > 0


class TestOIDValidation:
    def test_rejects_unknown_oid(self):
        from witnessos_verifier.der import validate_oid_acceptance
        result = validate_oid_acceptance((1, 2, 3, 99999))
        assert result is not None
        assert "not in allowed" in result

    def test_accepts_known_oid(self):
        from witnessos_verifier.der import validate_oid_acceptance, OID_SHA256
        result = validate_oid_acceptance(OID_SHA256)
        assert result is None  # Accepted


class TestTrustPolicyValidation:
    def test_demo_policy_allows_all(self):
        from witnessos_verifier.trust_policy import TrustPolicy, TrustLevel
        policy = TrustPolicy.demo()
        assert policy.is_tsa_allowed("https://freetsa.org/tsr")
        assert policy.is_tsa_allowed("https://any-tsa.example.com/tsa")
        assert not policy.requires_certificate_chain()

    def test_standard_policy_blocks_unlisted_tsa(self):
        from witnessos_verifier.trust_policy import TrustPolicy, TrustLevel
        policy = TrustPolicy(
            level=TrustLevel.STANDARD,
            label="test",
            allowed_tsa_urls={"https://allowed-tsa.example.com/tsa"},
        )
        assert not policy.is_tsa_allowed("https://evil-tsa.example.com/tsa")
        assert policy.is_tsa_allowed("https://allowed-tsa.example.com/tsa")

    def test_demo_policy_allows_all_hash_algorithms(self):
        from witnessos_verifier.trust_policy import TrustPolicy
        policy = TrustPolicy.demo()
        assert policy.is_hash_algorithm_allowed("2.16.840.1.101.3.4.2.1")  # SHA-256
        assert policy.is_hash_algorithm_allowed("2.16.840.1.101.3.4.2.2")  # SHA-384

    def test_demo_no_cert_chain_required(self):
        from witnessos_verifier.trust_policy import TrustPolicy
        policy = TrustPolicy.demo()
        assert not policy.requires_certificate_chain()
        assert not policy.requires_revocation_check()
