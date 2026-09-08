# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/empirelabs-au/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Test Ed25519 signature verification."""
import base64
import json
import nacl.signing
import nacl.encoding


class TestDetachedSignature:
    def test_valid_signature(self):
        from witnessos_verifier.signatures import verify_detached_signature

        sk = nacl.signing.SigningKey(b"exactly-thirty-two-bytes-1234567")
        pk = bytes(sk.verify_key).hex()
        msg = b"hello witnessos"
        signed = sk.sign(msg)
        sig_b64 = base64.b64encode(signed.signature).decode()

        assert verify_detached_signature(pk, msg, sig_b64)

    def test_bad_signature(self):
        from witnessos_verifier.signatures import verify_detached_signature

        sk = nacl.signing.SigningKey(b"exactly-thirty-two-bytes-1234567")
        pk = bytes(sk.verify_key).hex()
        msg = b"hello witnessos"
        bad_sig = base64.b64encode(b"\x00" * 64).decode()

        assert not verify_detached_signature(pk, msg, bad_sig)

    def test_wrong_message(self):
        from witnessos_verifier.signatures import verify_detached_signature

        sk = nacl.signing.SigningKey(b"exactly-thirty-two-bytes-1234567")
        pk = bytes(sk.verify_key).hex()
        signed = sk.sign(b"correct message")
        sig_b64 = base64.b64encode(signed.signature).decode()

        assert not verify_detached_signature(pk, b"wrong message", sig_b64)

    def test_wrong_key(self):
        sk1 = nacl.signing.SigningKey(b"exactly-thirty-two-bytes-1234567")
        sk2 = nacl.signing.SigningKey(b"another-thirty-two-bytes98765432")
        pk2 = bytes(sk2.verify_key).hex()
        signed = sk1.sign(b"hello")
        sig_b64 = base64.b64encode(signed.signature).decode()

        from witnessos_verifier.signatures import verify_detached_signature
        assert not verify_detached_signature(pk2, b"hello", sig_b64)


class TestEventSignaturesViaVerifier:
    def test_all_events_pass_verification(self, bundle_path):
        from witnessos_verifier.verifier import verify

        result = verify(bundle_path)
        assert "E2: Manifest signature valid" in result.grade.requirements_met
        assert result.manifest_result.signature_valid
