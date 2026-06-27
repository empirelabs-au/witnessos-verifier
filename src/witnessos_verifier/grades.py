"""Evidence grade derivation.

WitnessOS assigns evidence grades E1 through E4 based on what
has been cryptographically verified:

E1 — Observed: Events exist, loaded successfully
E2 — Internally validated: Case hash chain intact, ledger monotonic,
     event hashes verified, signatures valid
E3 — Destination acknowledged: Provider (Gmail, Stripe) confirmed the
     action via a provider_acknowledged or provider_confirmed event
E4 — Externally anchored: RFC 3161 timestamp + Merkle inclusion proof
     + WORM evidence copy — independently verifiable by anyone
"""

from dataclasses import dataclass
from typing import List, Optional

from .case_chain import ChainResult
from .ledger import LedgerResult
from .manifest import ManifestResult
from .timestamp import TimestampResult
from .worm import WormResult


class Grade:
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"


@dataclass
class GradeResult:
    grade: str
    display: str
    requirements_met: List[str]
    requirements_missing: List[str]

    @property
    def is_e4(self) -> bool:
        return self.grade == Grade.E4

    @property
    def is_minimum_e3(self) -> bool:
        return self.grade in (Grade.E3, Grade.E4)


def derive_grade(
    events_loaded: bool,
    chain_result: Optional[ChainResult],
    ledger_result: Optional[LedgerResult],
    manifest_result: Optional[ManifestResult],
    has_provider_ack: bool,
    timestamp_result: Optional[TimestampResult],
    worm_result: Optional[WormResult],
) -> GradeResult:
    """Derive the evidence grade from verification results.

    Grade progression is cumulative:
    E1: Events loaded successfully
    E2: E1 + chain valid + ledger valid + signatures valid
    E3: E2 + provider acknowledged the action
    E4: E3 + timestamp valid + Merkle proof valid + WORM copy valid
    """
    met = []
    missing = []

    # E1
    if events_loaded:
        met.append("E1: Events loaded")
    else:
        missing.append("E1: Events loaded")
        return GradeResult(grade="None", display="No evidence loaded",
                          requirements_met=met, requirements_missing=missing)

    grade = Grade.E1

    # E2
    e2_ok = True
    if chain_result and chain_result.valid:
        met.append("E2: Case hash chain valid")
    else:
        missing.append("E2: Case hash chain invalid")
        e2_ok = False

    if ledger_result and ledger_result.sequence_monotonic:
        met.append("E2: Ledger sequence valid")
    else:
        missing.append("E2: Ledger sequence invalid")
        e2_ok = False

    if manifest_result and manifest_result.valid:
        met.append("E2: Manifest signature valid")
    else:
        missing.append("E2: Manifest signature not verified")
        e2_ok = False

    if not e2_ok:
        return GradeResult(grade=Grade.E1, display="E1 — Observed",
                          requirements_met=met, requirements_missing=missing)
    grade = Grade.E2

    # E3
    if has_provider_ack:
        met.append("E3: Provider acknowledged")
        grade = Grade.E3
    else:
        missing.append("E3: No provider acknowledgement found")

    # E4
    e4_ok = True

    if timestamp_result and timestamp_result.valid and timestamp_result.imprint_matches:
        met.append("E4: RFC 3161 timestamp valid")
    else:
        missing.append("E4: RFC 3161 timestamp invalid or missing")
        e4_ok = False

    if worm_result and worm_result.valid:
        met.append("E4: WORM evidence copy valid")
    else:
        missing.append("E4: WORM evidence copy invalid or missing")
        e4_ok = False

    if e4_ok:
        # Return E4 regardless of E3 status (E4 subsumes E3)
        return GradeResult(
            grade=Grade.E4,
            display="E4 — Externally anchored",
            requirements_met=met,
            requirements_missing=missing,
        )

    if grade == Grade.E3:
        return GradeResult(
            grade=Grade.E3,
            display="E3 — Destination acknowledged",
            requirements_met=met,
            requirements_missing=missing,
        )

    return GradeResult(
        grade=Grade.E2,
        display="E2 — Internally validated",
        requirements_met=met,
        requirements_missing=missing,
    )
