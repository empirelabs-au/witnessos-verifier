"""WORM evidence bundle verification.

Verifies that WORM-stored evidence bundles have not been tampered with.
Each bundle contains a canonical hash that is compared against what
was recorded at storage time.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


class WormError(Exception):
    """WORM store verification error."""


@dataclass
class WormBundle:
    """A WORM evidence bundle record."""
    batch_id: str
    stored_hash: str
    stored_at: str
    case_id: str
    file_count: int
    file_hashes: Dict[str, str]


@dataclass
class WormResult:
    valid: bool
    bundle: WormBundle
    hash_matches: bool
    file_count_matches: bool
    errors: List[str]
    retention_verified: bool = False


def load_worm_bundle(worm_dir: Path) -> WormBundle:
    """Load a WORM evidence bundle from a directory."""
    store_file = worm_dir / "batch_store.json"
    if not store_file.exists():
        raise WormError(f"WORM store file not found: {store_file}")

    data = json.loads(store_file.read_text())
    return WormBundle(
        batch_id=data["batch_id"],
        stored_hash=data["stored_hash"],
        stored_at=data["stored_at"],
        case_id=data.get("case_id", ""),
        file_count=data.get("file_count", 0),
        file_hashes=data.get("file_hashes", {}),
    )


def verify_worm_bundle(worm_dir: Path, evidence_dir: Path) -> WormResult:
    """Verify a WORM evidence bundle against the original evidence.

    Checks:
    1. The WORM bundle file exists
    2. The stored hash matches the current evidence
    3. The file count matches
    """
    errors = []

    try:
        bundle = load_worm_bundle(worm_dir)
    except WormError as e:
        return WormResult(valid=False, bundle=None, hash_matches=False,
                          file_count_matches=False, errors=[str(e)])

    # Compute hash of all evidence files (excluding worm dir itself)
    evidence_files = sorted(evidence_dir.rglob("*"))
    computed_hash = hashlib.sha256()

    for f in evidence_files:
        if f.is_file() and f.relative_to(evidence_dir).parts[0] != "worm":
            computed_hash.update(f.read_bytes())

    current_hash = computed_hash.hexdigest()
    hash_ok = current_hash == bundle.stored_hash

    if not hash_ok:
        errors.append(
            f"WORM hash mismatch: stored={bundle.stored_hash[:16]}..., "
            f"current={current_hash[:16]}..."
        )

    # Count files (excluding worm dir)
    current_count = sum(1 for f in evidence_files if f.is_file() and f.relative_to(evidence_dir).parts[0] != "worm")
    count_ok = current_count == bundle.file_count

    if not count_ok:
        errors.append(
            f"File count mismatch: stored={bundle.file_count}, "
            f"current={current_count}"
        )

    return WormResult(
        valid=len(errors) == 0,
        bundle=bundle,
        hash_matches=hash_ok,
        file_count_matches=count_ok,
        errors=errors,
    )
