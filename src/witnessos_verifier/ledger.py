# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/empirelabs-au/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Global ledger verification.

Verifies that events are part of a valid global ledger with
monotonic sequence numbers and consistent head hashes.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .events import Event


class LedgerError(Exception):
    """Global ledger verification error."""


@dataclass
class LedgerHead:
    """The head state of the global ledger."""
    head_seq: int
    head_hash: str
    total_events: int
    batches: int
    anchored_batches: int


@dataclass
class LedgerResult:
    """Result of global ledger verification."""
    valid: bool
    sequence_monotonic: bool
    head_consistent: bool
    head: Optional[LedgerHead] = None
    errors: List[str] = field(default_factory=list)


def verify_ledger_sequence(events: List[Event]) -> LedgerResult:
    """Verify global ledger sequence monotonicity.

    Checks that event sequence numbers form a gapless chain.
    """
    errors = []
    if not events:
        return LedgerResult(valid=False, sequence_monotonic=False,
                            head_consistent=False,
                            errors=["No events to verify"])

    seqs = [e.seq for e in events]
    expected = seqs[0]  # Global start seq, not necessarily 0

    for i, seq in enumerate(seqs):
        if seq != expected:
            errors.append(
                f"Sequence gap: expected {expected}, got {seq} "
                f"at event {events[i].event_id}"
            )
        expected = seq + 1

    return LedgerResult(
        valid=len(errors) == 0,
        sequence_monotonic=len(errors) == 0,
        head_consistent=True,  # Base check: head consistency requires batch data
        head=LedgerHead(
            head_seq=seqs[-1],
            head_hash=events[-1].canonical_hash,
            total_events=len(events),
            batches=0,
            anchored_batches=0,
        ),
        errors=errors,
    )
