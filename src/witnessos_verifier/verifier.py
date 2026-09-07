"""WitnessOS Verifier — Main orchestrator.

Verifies a complete WitnessOS evidence bundle end-to-end.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .case_chain import verify_case_chain, ChainResult
from .events import load_events, Event, EventError
from .grades import derive_grade, GradeResult
from .key_registry import KeyRegistry, KeyRegistryError
from .ledger import verify_ledger_sequence, LedgerResult
from .manifest import BatchManifest, verify_manifest, ManifestResult
from .merkle import MerkleError
from .timestamp import verify_timestamp, TimestampResult, TimestampError
from .worm import verify_worm_bundle, WormResult, WormError


class VerifyError(Exception):
    """Top-level verification error."""


@dataclass
class VerifyResult:
    """Complete verification result."""
    bundle_path: Path
    valid: bool
    grade: Optional[GradeResult] = None
    events: List[Event] = field(default_factory=list)
    chain_result: Optional[ChainResult] = None
    ledger_result: Optional[LedgerResult] = None
    manifest_result: Optional[ManifestResult] = None
    timestamp_result: Optional[TimestampResult] = None
    worm_result: Optional[WormResult] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def evidence_grade(self) -> str:
        if self.grade:
            return self.grade.grade
        return "NONE"

    def summary(self) -> str:
        lines = []
        lines.append(f"Bundle: {self.bundle_path}")
        lines.append(f"Grade:  {self.evidence_grade}")
        lines.append(f"Events: {len(self.events)}")

        if self.chain_result:
            status = "PASS" if self.chain_result.valid else "FAIL"
            lines.append(f"  Chain:   {status} ({self.chain_result.verified_links}/{self.chain_result.total_events} links)")

        if self.ledger_result:
            status = "PASS" if self.ledger_result.sequence_monotonic else "FAIL"
            lines.append(f"  Ledger:  {status}")

        if self.manifest_result:
            status = "PASS" if self.manifest_result.valid else "FAIL"
            lines.append(f"  Manifest: {status}")

        if self.timestamp_result:
            status = "PASS" if self.timestamp_result.valid else "FAIL"
            lines.append(f"  TSA:     {status}")
            if self.timestamp_result.trust_policy_result:
                tr = self.timestamp_result.trust_policy_result
                lines.append(f"  Trust:   {tr.trust_level} → {tr.revocation_status.value}")

        if self.worm_result:
            status = "PASS" if self.worm_result.valid else "FAIL"
            lines.append(f"  WORM:    {status}")

        if self.errors:
            lines.append("")
            lines.append("Errors:")
            for e in self.errors:
                lines.append(f"  ✗ {e}")

        return "\n".join(lines)


def verify(bundle_path: Path, alpha_mode: bool = False) -> VerifyResult:
    """Verify a WitnessOS evidence bundle.

    The bundle must contain:
    - events/           Directory of event JSON files
    - keys.json         Public key registry
    - case_manifest.json  Case metadata
    - batch_manifest.json  Batch manifest with signature
    - timestamp/         RFC 3161 timestamp token(s)
    - worm/              WORM evidence bundle

    Returns a VerifyResult with grade and all sub-results.
    """
    errors = []
    warnings = []
    bundle_path = bundle_path.resolve()

    if not bundle_path.exists():
        raise VerifyError(f"Bundle directory not found: {bundle_path}")
    if not bundle_path.is_dir():
        raise VerifyError(f"Not a directory: {bundle_path}")

    # 1. Load events
    try:
        events = load_events(bundle_path)
    except EventError as e:
        return VerifyResult(
            bundle_path=bundle_path,
            valid=False,
            errors=[str(e)],
        )
    if not events:
        return VerifyResult(
            bundle_path=bundle_path,
            valid=False,
            errors=["No events found in bundle"],
        )
    events_loaded = True

    # 2. Load key registry
    key_registry = None
    keys_path = bundle_path / "keys.json"
    if keys_path.exists():
        try:
            key_registry = KeyRegistry.from_file(keys_path)
        except KeyRegistryError as e:
            warnings.append(f"Key registry: {e}")
    else:
        warnings.append("No keys.json found — signatures cannot be verified")

    # 3. Verify case hash chain
    chain_result = verify_case_chain(events)

    # 4. Verify ledger sequence
    ledger_result = verify_ledger_sequence(events)

    # 5. Verify manifest
    manifest_result = None
    manifest_path = bundle_path / "batch_manifest.json"
    if manifest_path.exists():
        try:
            manifest = BatchManifest.from_file(manifest_path)
            if key_registry:
                manifest_result = verify_manifest(manifest, key_registry)
            else:
                warnings.append("Cannot verify manifest: no key registry")
        except Exception as e:
            warnings.append(f"Manifest verification skipped: {e}")
    else:
        warnings.append("No batch_manifest.json found")

    # 6. Check for provider acknowledgement
    # Accept BOTH naming conventions: the current engine vocabulary is
    # dot-separated (provider.acknowledged / provider.confirmed) while older
    # bundles used underscores (provider_acknowledged / provider_confirmed).
    has_provider_ack = any(
        e.event_type in (
            "provider.acknowledged", "provider.confirmed",
            "provider_acknowledged", "provider_confirmed",
        )
        for e in events
    )

    # 7. Verify timestamp token
    timestamp_result = None
    ts_dir = bundle_path / "timestamp"
    if ts_dir.exists():
        ts_files = list(ts_dir.glob("*.tsr")) + list(ts_dir.glob("*.der"))
        if ts_files:
            # Use batch manifest root hash as expected imprint
            expected_hash = None
            if manifest_path.exists():
                try:
                    with open(manifest_path) as f:
                        mdata = json.load(f)
                        root = mdata.get("root", "")
                        if root:
                            # TSA timestamps SHA-256(root), not root directly
                            root_bytes = bytes.fromhex(root)
                            expected_hash = hashlib.sha256(root_bytes).digest()
                except Exception:
                    pass

            if expected_hash:
                try:
                    timestamp_result = verify_timestamp(ts_files[0], expected_hash)
                except Exception as e:
                    warnings.append(f"Timestamp verification error: {e}")
            else:
                warnings.append("Cannot verify timestamp: no expected hash from manifest")
        else:
            warnings.append("Timestamp directory exists but no .tsr/.der files found")

    # 8. Verify WORM bundle
    worm_result = None
    worm_dir = bundle_path / "worm"
    if worm_dir.exists():
        try:
            worm_result = verify_worm_bundle(worm_dir, bundle_path)
        except Exception as e:
            warnings.append(f"WORM verification error: {e}")

    # 9. Derive grade
    grade = derive_grade(
        events_loaded=events_loaded,
        chain_result=chain_result,
        ledger_result=ledger_result,
        manifest_result=manifest_result,
        has_provider_ack=has_provider_ack,
        timestamp_result=timestamp_result,
        worm_result=worm_result,
        alpha_mode=alpha_mode,
    )

    # Collect all errors
    if chain_result and chain_result.errors:
        errors.extend(chain_result.errors)
    if ledger_result and ledger_result.errors:
        errors.extend(ledger_result.errors)
    if manifest_result and manifest_result.errors:
        errors.extend(manifest_result.errors)
    if timestamp_result and timestamp_result.errors:
        errors.extend(timestamp_result.errors)
    if worm_result and worm_result.errors:
        errors.extend(worm_result.errors)

    return VerifyResult(
        bundle_path=bundle_path,
        valid=len(errors) == 0,
        grade=grade,
        events=events,
        chain_result=chain_result,
        ledger_result=ledger_result,
        manifest_result=manifest_result,
        timestamp_result=timestamp_result,
        worm_result=worm_result,
        errors=errors,
        warnings=warnings,
    )
