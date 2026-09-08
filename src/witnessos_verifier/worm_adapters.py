# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/empirelabs-au/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""WORM storage adapters for WitnessOS evidence retention.

Provides pluggable storage backends for the WORM evidence vault:
  - LocalWORM: reference/demo adapter (filesystem + hash chain)
  - S3ObjectLockWORM: production adapter (S3 Object Lock with compliance retention)

The adapter interface is:
  - store(evidence_id: str, data: bytes) -> str  # returns storage location
  - retrieve(evidence_id: str) -> Optional[bytes]
  - verify_integrity() -> List[str]  # returns list of issues
  - is_immutable() -> bool
"""

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# --- WORM Adapter Interface ---

class WORMAdapter(ABC):
    """Abstract interface for WORM storage backends."""

    @abstractmethod
    def store(self, evidence_id: str, data: bytes) -> str:
        """Store evidence. Returns a storage location identifier."""

    @abstractmethod
    def retrieve(self, evidence_id: str) -> Optional[bytes]:
        """Retrieve evidence by ID."""

    @abstractmethod
    def verify_integrity(self) -> List[str]:
        """Verify stored evidence integrity. Returns list of issues."""

    @abstractmethod
    def is_immutable(self) -> bool:
        """Whether this backend provides immutable retention guarantees."""

    @abstractmethod
    def get_manifest(self) -> Dict:
        """Return a verifiable manifest of stored evidence."""


# --- Local Filesystem WORM (Reference/Demo) ---

@dataclass
class LocalWORM(WORMAdapter):
    """Reference implementation using local filesystem with hash-chain integrity.

    Stores each evidence item as a file and maintains a chain of SHA-256 hashes.
    This is suitable for demonstration and testing, not for enterprise-grade
    immutability (a compromised host could alter files).
    """

    root_dir: Path
    hash_chain: List[str] = field(default_factory=list)
    _manifest: Dict[str, str] = field(default_factory=dict)  # evidence_id → sha256

    def __post_init__(self):
        self.root_dir.mkdir(parents=True, exist_ok=True)
        # Load existing manifest if present
        manifest_path = self.root_dir / "batch_store.json"
        if manifest_path.exists():
            try:
                data = json.loads(manifest_path.read_text())
                self._manifest = data.get("evidence", {})
                self.hash_chain = data.get("chain", [])
            except (json.JSONDecodeError, KeyError):
                pass

    def store(self, evidence_id: str, data: bytes) -> str:
        store_path = self.root_dir / evidence_id
        store_path.write_bytes(data)

        file_hash = hashlib.sha256(data).hexdigest()
        self._manifest[evidence_id] = file_hash
        self.hash_chain.append(file_hash)

        # Persist manifest
        self._write_manifest()

        return str(store_path)

    def retrieve(self, evidence_id: str) -> Optional[bytes]:
        store_path = self.root_dir / evidence_id
        if not store_path.exists():
            return None
        return store_path.read_bytes()

    def verify_integrity(self) -> List[str]:
        issues = []
        for ev_id, expected_hash in self._manifest.items():
            path = self.root_dir / ev_id
            if not path.exists():
                issues.append(f"Missing evidence: {ev_id}")
                continue
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                issues.append(f"Hash mismatch for {ev_id}: expected {expected_hash}, got {actual_hash}")
        return issues

    def is_immutable(self) -> bool:
        return False  # Local filesystem is not truly immutable

    def get_manifest(self) -> Dict:
        return {
            "evidence": dict(self._manifest),
            "chain": list(self.hash_chain),
            "count": len(self._manifest),
            "adapter": "local",
            "immutable": False,
        }

    def _write_manifest(self):
        manifest_path = self.root_dir / "batch_store.json"
        manifest_path.write_text(json.dumps(self.get_manifest(), indent=2))


# --- S3 Object Lock WORM (Enterprise) ---

class S3ObjectLockWORM(WORMAdapter):
    """Enterprise WORM storage using S3 Object Lock with compliance retention.

    Requires the 'boto3' package. Configuration is passed as kwargs:
      - bucket: S3 bucket name
      - prefix: optional key prefix within the bucket
      - retention_mode: 'GOVERNANCE' or 'COMPLIANCE'
      - retention_days: number of days to retain objects
      - region: AWS region (optional)
      - endpoint_url: for S3-compatible storage (MinIO, etc.)

    Object Lock must be enabled on the bucket at creation time.
    Compliance mode prevents deletion by any user, including root.
    """

    def __init__(self, **config):
        try:
            import boto3
            from botocore.config import Config as BotoConfig
            from botocore.exceptions import ClientError
        except ImportError:
            raise ImportError(
                "boto3 is required for S3 WORM storage. "
                "Install with: pip install witnessos-verifier[s3]"
            )

        self.config = config
        self.bucket = config["bucket"]
        self.prefix = config.get("prefix", "evidence/")
        self.retention_mode = config.get("retention_mode", "COMPLIANCE")
        self.retention_days = config.get("retention_days", 2555)  # ~7 years

        boto_config = BotoConfig(
            region_name=config.get("region", "us-east-1"),
            retries={"max_attempts": 3},
        )

        s3_kwargs = {"config": boto_config}
        if "endpoint_url" in config:
            s3_kwargs["endpoint_url"] = config["endpoint_url"]

        self.client = boto3.client("s3", **s3_kwargs)

        # Verify the bucket exists and has Object Lock enabled
        self._verify_bucket()

    def _verify_bucket(self):
        """Verify the bucket exists and supports Object Lock."""
        try:
            self.client.head_bucket(Bucket=self.bucket)
            ol_config = self.client.get_object_lock_configuration(
                Bucket=self.bucket
            )
            logger.info(
                f"S3 bucket '{self.bucket}' confirmed with Object Lock enabled"
            )
        except self.client.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ObjectLockConfigurationNotFoundError":
                logger.warning(
                    f"Bucket '{self.bucket}' exists but Object Lock may not "
                    f"be enabled. Evidence stored without Lock will not be immutable."
                )
            elif code == "404":
                raise ValueError(
                    f"S3 bucket '{self.bucket}' not found"
                )
            else:
                raise

    def store(self, evidence_id: str, data: bytes) -> str:
        key = f"{self.prefix}{evidence_id}"
        content_sha256 = hashlib.sha256(data).hexdigest()

        # Store with Object Lock retention
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
            ContentSHA256=content_sha256,
            ObjectLockMode=self.retention_mode,
            ObjectLockRetainUntilDate=datetime.now(timezone.utc) + \
                __import__("datetime").timedelta(days=self.retention_days),
            Metadata={"sha256": content_sha256},
        )

        location = f"s3://{self.bucket}/{key}"
        logger.info(f"Stored evidence '{evidence_id}' at {location}")
        return location

    def retrieve(self, evidence_id: str) -> Optional[bytes]:
        key = f"{self.prefix}{evidence_id}"
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
            return response["Body"].read()
        except self.client.exceptions.NoSuchKey:
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve '{evidence_id}': {e}")
            return None

    def verify_integrity(self) -> List[str]:
        """Verify all stored evidence matches its SHA-256 metadata."""
        issues: List[str] = []
        try:
            paginator = self.client.get_paginator("list_objects_v2")
            for page in paginator.paginate(
                Bucket=self.bucket, Prefix=self.prefix
            ):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    evidence_id = key.replace(self.prefix, "")

                    # Get object metadata
                    head = self.client.head_object(Bucket=self.bucket, Key=key)
                    expected_hash = head.get("Metadata", {}).get("sha256", "")

                    if not expected_hash:
                        issues.append(
                            f"No SHA-256 metadata for {key}"
                        )
                        continue

                    # Verify by retrieving and hashing
                    data = self.retrieve(evidence_id)
                    if data is None:
                        issues.append(f"Unable to retrieve {key} for verification")
                        continue

                    actual_hash = hashlib.sha256(data).hexdigest()
                    if actual_hash != expected_hash:
                        issues.append(
                            f"Hash mismatch for {key}: "
                            f"expected {expected_hash}, got {actual_hash}"
                        )

                    # Verify Object Lock retention is still active
                    try:
                        retention = head.get("ObjectLockRetainUntilDate")
                        if retention:
                            now = datetime.now(timezone.utc)
                            if retention < now:
                                issues.append(
                                    f"Object Lock expired for {key} "
                                    f"(retained until {retention.isoformat()})"
                                )
                    except Exception:
                        pass

        except Exception as e:
            issues.append(f"S3 integrity scan failed: {e}")

        return issues

    def is_immutable(self) -> bool:
        return True  # S3 Object Lock provides legal immutability

    def get_manifest(self) -> Dict:
        manifest: Dict[str, str] = {}
        try:
            paginator = self.client.get_paginator("list_objects_v2")
            for page in paginator.paginate(
                Bucket=self.bucket, Prefix=self.prefix
            ):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    evidence_id = key.replace(self.prefix, "")
                    etag = obj.get("ETag", "").strip('"')
                    manifest[evidence_id] = f"sha256:{etag}"
        except Exception as e:
            logger.error(f"Failed to build manifest: {e}")

        return {
            "evidence": manifest,
            "count": len(manifest),
            "adapter": "s3-object-lock",
            "bucket": self.bucket,
            "prefix": self.prefix,
            "retention_mode": self.retention_mode,
            "retention_days": self.retention_days,
            "immutable": True,
        }


# --- Adapter Factory ---

def create_worm_adapter(adapter_type: str, **config) -> WORMAdapter:
    """Create a WORM adapter by type.

    Supported types:
      - 'local': LocalWORM (default, reference/demo)
      - 's3': S3ObjectLockWORM (enterprise)

    Args:
        adapter_type: 'local' or 's3'
        **config: Adapter-specific configuration

    Returns:
        A WORMAdapter instance
    """
    adapters = {
        "local": LocalWORM,
        "s3": S3ObjectLockWORM,
    }

    if adapter_type not in adapters:
        raise ValueError(
            f"Unknown WORM adapter '{adapter_type}'. "
            f"Available: {list(adapters.keys())}"
        )

    return adapters[adapter_type](**config)
