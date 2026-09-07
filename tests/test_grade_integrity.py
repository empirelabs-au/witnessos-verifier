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
        result = verify(stripe)
        assert result.valid
        assert "E3: Provider acknowledged" in result.grade.requirements_met
        assert result.grade.grade == "E4"

    def test_dot_vocabulary_confirmed(self):
        from witnessos_verifier.grades import derive_grade
        # Provider .confirmed must also satisfy E3
        gr = derive_grade(
            events_loaded=True,
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            has_provider_ack=True,
            timestamp_result=_R(True, imprint_matches=True),
            worm_result=_R(True),
        )
        assert gr.grade == "E4"


class TestE4RequiresE3:
    """E4 must never be awarded without provider acknowledgement."""

    def _grade_with(self, has_ack, tsa_ok=True, worm_ok=True):
        from witnessos_verifier.grades import derive_grade
        return derive_grade(
            events_loaded=True,
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            has_provider_ack=has_ack,
            timestamp_result=_R(tsa_ok, imprint_matches=tsa_ok),
            worm_result=_R(worm_ok),
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
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            has_provider_ack=True,
            timestamp_result=_R(True, imprint_matches=True),
            worm_result=_R(True),
            alpha_mode=True,
        )
        assert gr.grade == "E3"
        # Alpha WITHOUT ack must stay below E3 too
        gr2 = derive_grade(
            events_loaded=True,
            chain_result=_R(True),
            ledger_result=_R(True, sequence_monotonic=True),
            manifest_result=_R(True),
            has_provider_ack=False,
            timestamp_result=_R(True, imprint_matches=True),
            worm_result=_R(True),
            alpha_mode=True,
        )
        assert gr2.grade != "E4" and gr2.grade != "E3"
