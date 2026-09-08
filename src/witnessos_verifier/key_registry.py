# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/empirelabs-au/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Key registry for WitnessOS verification.

Manages public keys used for signature verification.
Keys are loaded from the evidence bundle's keys.json file.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .signatures import KeyStatus


class KeyRegistryError(Exception):
    """Key registry error."""


@dataclass
class KeyRecord:
    key_id: str
    public_key_hex: str
    status: str
    algorithm: str = "Ed25519"
    created_at: Optional[str] = None
    revoked_at: Optional[str] = None
    description: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return self.status in KeyStatus.valid_statuses()

    @property
    def public_key_bytes(self) -> bytes:
        return bytes.fromhex(self.public_key_hex)


class KeyRegistry:
    """A registry of public keys loaded from a bundle."""

    def __init__(self):
        self._keys: Dict[str, KeyRecord] = {}

    def add_key(self, key: KeyRecord) -> None:
        self._keys[key.key_id] = key

    def get_key(self, key_id: str) -> Optional[KeyRecord]:
        return self._keys.get(key_id)

    def has_key(self, key_id: str) -> bool:
        return key_id in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    @classmethod
    def from_file(cls, path: Path) -> "KeyRegistry":
        """Load keys from a keys.json file."""
        if not path.exists():
            raise KeyRegistryError(f"Keys file not found: {path}")

        data = json.loads(path.read_text())
        registry = cls()

        keys = data if isinstance(data, list) else data.get("keys", [])
        for k in keys:
            record = KeyRecord(
                key_id=k["key_id"],
                public_key_hex=k["public_key_hex"],
                status=k.get("status", KeyStatus.ACTIVE),
                algorithm=k.get("algorithm", "Ed25519"),
                created_at=k.get("created_at"),
                revoked_at=k.get("revoked_at"),
                description=k.get("description"),
            )
            registry.add_key(record)

        if not registry._keys:
            raise KeyRegistryError("No keys found in keys file")

        return registry

    @classmethod
    def from_dict(cls, data: list) -> "KeyRegistry":
        """Create a KeyRegistry from a list of key dicts (for testing)."""
        registry = cls()
        for k in data:
            record = KeyRecord(
                key_id=k["key_id"],
                public_key_hex=k["public_key_hex"],
                status=k.get("status", KeyStatus.ACTIVE),
                algorithm=k.get("algorithm", "Ed25519"),
                created_at=k.get("created_at"),
                revoked_at=k.get("revoked_at"),
                description=k.get("description"),
            )
            registry.add_key(record)
        return registry
