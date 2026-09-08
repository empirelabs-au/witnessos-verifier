# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/empirelabs-au/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Signed batch manifest verification.

Batch manifests record all events in a batch and are signed by
the batch signing key. The manifest signature proves the batch
was produced by an authorised WitnessOS instance.
"""

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .key_registry import KeyRegistry
from .signatures import verify_detached_signature


class ManifestError(Exception):
    """Manifest verification error."""


@dataclass
class BatchManifest:
    batch_id: str
    signing_key_id: str
    case_id: str
    root: str
    prev_root: str
    event_ids: List[str]
    start_seq: int
    end_seq: int
    signed_at: str
    signature: str

    @classmethod
    def from_file(cls, path: Path) -> "BatchManifest":
        if not path.exists():
            raise ManifestError(f"Manifest file not found: {path}")

        data = json.loads(path.read_text())
        required = ["batch_id", "signing_key_id", "root", "event_ids",
                    "start_seq", "end_seq", "signed_at", "signature"]
        for field_name in required:
            if field_name not in data:
                raise ManifestError(f"Missing required field '{field_name}' in manifest")

        return cls(
            batch_id=data["batch_id"],
            signing_key_id=data["signing_key_id"],
            case_id=data.get("case_id", ""),
            root=data["root"],
            prev_root=data.get("prev_root", ""),
            event_ids=data["event_ids"],
            start_seq=data["start_seq"],
            end_seq=data["end_seq"],
            signed_at=data["signed_at"],
            signature=data["signature"],
        )

    @property
    def signed_data(self) -> bytes:
        """The data that was signed to produce the manifest signature."""
        obj = {
            "batch_id": self.batch_id,
            "signing_key_id": self.signing_key_id,
            "case_id": self.case_id,
            "root": self.root,
            "prev_root": self.prev_root,
            "event_ids": self.event_ids,
            "start_seq": self.start_seq,
            "end_seq": self.end_seq,
            "signed_at": self.signed_at,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class ManifestResult:
    valid: bool
    manifest: BatchManifest
    key_found: bool
    key_valid: bool
    signature_valid: bool
    errors: List[str]


def verify_manifest(manifest: BatchManifest, key_registry: KeyRegistry) -> ManifestResult:
    """Verify a batch manifest signature."""
    errors = []

    # Check key exists
    key = key_registry.get_key(manifest.signing_key_id)
    if key is None:
        return ManifestResult(
            valid=False,
            manifest=manifest,
            key_found=False,
            key_valid=False,
            signature_valid=False,
            errors=[f"Key {manifest.signing_key_id} not found in key registry"],
        )

    if not key.is_valid:
        errors.append(f"Key {manifest.signing_key_id} is {key.status}")

    # Verify signature
    sig_valid = verify_detached_signature(
        key.public_key_hex,
        manifest.signed_data,
        manifest.signature,
    )
    if not sig_valid:
        errors.append(f"Manifest signature invalid for key {manifest.signing_key_id}")

    return ManifestResult(
        valid=len(errors) == 0,
        manifest=manifest,
        key_found=True,
        key_valid=key.is_valid,
        signature_valid=sig_valid,
        errors=errors,
    )
