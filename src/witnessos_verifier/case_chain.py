# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/empirelabs-au/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Case hash chain verification.

Each event in a case links to the previous one via prev_hash.
The case chain is verified by walking all events and confirming
each prev_hash matches the canonical hash of the previous event.
"""

import hashlib
from dataclasses import dataclass
from typing import List

from .events import Event


class ChainError(Exception):
    """Case hash chain verification error."""


@dataclass
class ChainResult:
    """Result of case hash chain verification."""
    valid: bool
    total_events: int
    verified_links: int
    errors: List[str]


def verify_case_chain(events: List[Event]) -> ChainResult:
    """Verify the hash chain for a case.

    Genesis events (seq=0) must have prev_hash equal to the
    SHA-256 of the empty string.
    """
    errors = []
    verified = 0

    if not events:
        return ChainResult(valid=False, total_events=0, verified_links=0,
                           errors=["No events to verify"])

    # Genesis event
    genesis = events[0]
    if genesis.seq == 0:
        expected_genesis_prev = hashlib.sha256(b"").hexdigest()
        if genesis.prev_hash != expected_genesis_prev:
            errors.append(
                f"Genesis event {genesis.event_id}: prev_hash mismatch — "
                f"expected sha256('')={expected_genesis_prev[:16]}..., "
                f"got {genesis.prev_hash[:16]}..."
            )
        else:
            verified += 1

    # Subsequent events
    for i in range(1, len(events)):
        prev = events[i - 1]
        current = events[i]
        expected_prev = prev.canonical_hash

        if current.prev_hash != expected_prev:
            errors.append(
                f"Event {current.event_id} (seq {current.seq}): "
                f"prev_hash {current.prev_hash[:16]}... does not match "
                f"previous event hash {expected_prev[:16]}..."
            )
        else:
            verified += 1

    return ChainResult(
        valid=len(errors) == 0,
        total_events=len(events),
        verified_links=verified,
        errors=errors,
    )
