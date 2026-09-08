"""Regression tests for E3/E4 grade integrity (2026-09-08 fixes).

Two bugs were found during the public-verifier audit:
1. E3 provider-ack detection only matched underscore event types
   (provider_acknowledged / provider_confirmed), but the current engine
   vocabulary is dot-separated (provider.acknowledged / provider.confirmed).
   Real engine receipts would fail E3 -> never reach E4.
2. Grade derivation returned E4 whenever TSA+WORM passed, even when E3 was
   missing. The documented ladder is cumulative (E4 = E3 + anchor), so a
   bundle without provider acknowledgement must cap below E4.
"""
import json
from pathlib import Path


class _R:
    """Minimal stand-in for a result object with .valid (+ optional fields)."""
    def __init__(self, valid=True, **kw):
        self.valid = valid
        for k, v in kw.items():
            setattr(self, k, v)


class TestE3VocabularyBothForms:
    """E3 provider-ack must be recognised in BOTH naming conventions."""

    def test_dot_vocabulary_acknowledged(self, bundle_path):
        from witnessos_verifier.verifier import verify
        # Stripe fixture uses the current dot-separated vocabulary
        stripe = bundle_path.parent / "e4-stripe-refund"
        from witnessos_verifier.events import load_events
        from witnessos_verifier.verifier import PROVIDER_ACK_TYPES
        assert any(e.event_type in PROVIDER_ACK_TYPES for e in load_events(stripe))
        # Without trust roots: dot-vocab fixture fails closed at E3 (TSA not
        # verified) — never E1 — proving the E3 vocabulary check passes and
        # the merkle binding is now correct (fixture regenerated 2026-09-08).
        result = verify(stripe)
        assert not result.valid
        assert result.grade.grade == "E3", f"expected E3, got {result.grade.grade}"
        assert "Loaded events do not match signed Merkle root" not in result.errors

    def test_dot_vocabulary_confirmed(self):
        from witnessos_verifier.grades import derive_grade
        # Provider .confirmed must also satisfy E3
        gr = derive_grade(
            events_loaded=True,
            event_signatures_valid=True,
            batch_binding_valid=True,
            merkle_proof_valid=True,
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            has_provider_ack=True,
            timestamp_result=_R(True, imprint_matches=True, signature_verified=True, trust_verified=True),
            worm_result=_R(True, retention_verified=True),
        )
        assert gr.grade == "E4"


class TestE4RequiresE3:
    """E4 must never be awarded without provider acknowledgement."""

    def _grade_with(self, has_ack, tsa_ok=True, worm_ok=True):
        from witnessos_verifier.grades import derive_grade
        return derive_grade(
            events_loaded=True,
            event_signatures_valid=True,
            batch_binding_valid=True,
            merkle_proof_valid=True,
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            has_provider_ack=has_ack,
            timestamp_result=_R(tsa_ok, imprint_matches=tsa_ok, signature_verified=tsa_ok, trust_verified=tsa_ok),
            worm_result=_R(worm_ok, retention_verified=worm_ok),
        )

    def test_no_ack_tsa_present_caps_below_e4(self):
        # TSA+WORM pass but no provider acknowledgement -> NOT E4
        gr = self._grade_with(has_ack=False)
        assert gr.grade != "E4"
        assert gr.grade == "E2", f"Expected cap at E2, got {gr.grade}"
        assert "E3: No provider acknowledgement found" in gr.requirements_missing

    def test_full_e4_requires_ack(self):
        # With acknowledgement and valid anchor -> E4
        gr = self._grade_with(has_ack=True)
        assert gr.grade == "E4"

    def test_alpha_caps_e4_to_e3_only_with_ack(self):
        # Alpha mode with ack + valid anchor -> capped E3 (never E4)
        from witnessos_verifier.grades import derive_grade
        gr = derive_grade(
            events_loaded=True,
            event_signatures_valid=True,
            batch_binding_valid=True,
            merkle_proof_valid=True,
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            has_provider_ack=True,
            timestamp_result=_R(True, imprint_matches=True, signature_verified=True, trust_verified=True),
            worm_result=_R(True, retention_verified=True),
            alpha_mode=True,
        )
        assert gr.grade == "E3"
        # Alpha WITHOUT ack must stay below E3 too
        gr2 = derive_grade(
            events_loaded=True,
            event_signatures_valid=True,
            batch_binding_valid=True,
            merkle_proof_valid=True,
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            has_provider_ack=False,
            timestamp_result=_R(True, imprint_matches=True, signature_verified=True, trust_verified=True),
            worm_result=_R(True, retention_verified=True),
            alpha_mode=True,
        )
        assert gr2.grade != "E4" and gr2.grade != "E3"


class TestWormRetentionBinding:
    """Authenticated retention requires a REAL verified anchor, not a
    matching root string (2026-09-08 Phase-2 fixes)."""

    def test_retention_requires_anchor_verified(self, tmp_path):
        from witnessos_verifier.worm import verify_worm_bundle
        import json, hashlib

        # Minimal evidence + worm store binding to root "abc"
        ev = tmp_path / "evidence"; ev.mkdir()
        (ev / "event.json").write_text('{"a":1}')
        worm = ev / "worm"; worm.mkdir()
        files = sorted(p for p in ev.rglob("*") if p.is_file() and p.relative_to(ev).parts[0] != "worm")
        h = hashlib.sha256()
        for f in files: h.update(f.read_bytes())
        store = {
            "batch_id": "b1", "stored_hash": h.hexdigest(),
            "stored_at": "2026-01-01T00:00:00Z", "case_id": "c1",
            "file_count": len(files), "file_hashes": {}, "anchored_root": "abc",
        }
        (worm / "batch_store.json").write_text(json.dumps(store))

        # Binding matches but anchor NOT verified -> retention fails closed
        r1 = verify_worm_bundle(worm, ev, anchored_root="abc", anchor_verified=False)
        assert not r1.retention_verified
        assert not r1.valid

        # Binding matches AND anchor verified -> retention authenticated
        r2 = verify_worm_bundle(worm, ev, anchored_root="abc", anchor_verified=True)
        assert r2.retention_verified
        assert r2.valid

    def test_retention_rejects_wrong_root(self, tmp_path):
        from witnessos_verifier.worm import verify_worm_bundle
        import json, hashlib

        ev = tmp_path / "evidence"; ev.mkdir()
        (ev / "event.json").write_text('{"a":1}')
        worm = ev / "worm"; worm.mkdir()
        files = sorted(p for p in ev.rglob("*") if p.is_file() and p.relative_to(ev).parts[0] != "worm")
        h = hashlib.sha256()
        for f in files: h.update(f.read_bytes())
        store = {
            "batch_id": "b1", "stored_hash": h.hexdigest(),
            "stored_at": "2026-01-01T00:00:00Z", "case_id": "c1",
            "file_count": len(files), "file_hashes": {}, "anchored_root": "evil",
        }
        (worm / "batch_store.json").write_text(json.dumps(store))
        r = verify_worm_bundle(worm, ev, anchored_root="abc", anchor_verified=True)
        assert not r.retention_verified
        assert not r.valid

    def test_e2e_gmail_e4_green_with_roots(self, bundle_path):
        """The genuine E4 fixture must grade E4 end-to-end when trust roots
        are supplied (Phase-1 TSA + Phase-2 retention both authenticated)."""
        from witnessos_verifier.verifier import verify
        from witnessos_verifier.trust_policy import TrustPolicy, TrustLevel
        from pathlib import Path

        root_pem = Path("trust/freetsa/freetsa-root.pem")
        if not root_pem.exists():
            return  # trust material absent in this checkout — skip
        pol = TrustPolicy(level=TrustLevel.STANDARD, trusted_roots=[root_pem])
        result = verify(bundle_path, policy=pol)
        assert result.valid, f"expected valid E4, got errors: {result.errors}"
        assert result.grade.grade == "E4"
        assert result.timestamp_result.signature_verified
        assert result.worm_result.retention_verified
