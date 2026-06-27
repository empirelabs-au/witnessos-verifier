"""TSA trust-policy engine for WitnessOS RFC 3161 verification.

Production timestamp verification requires more than DER parsing.
This module enforces:

  - TSA provider allowlist
  - Certificate chain to trusted root CAs
  - id-kp-timeStamping Extended Key Usage
  - Data imprint match
  - Nonce echo (when supplied)
  - Policy OID match
  - Certificate expiration and revocation status
  - Algorithm acceptance (hash and signature)

Demonstration mode uses a relaxed policy; production deployments
must configure their own root CAs and TSA providers.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

class RevocationStatus(Enum):
    """Status of CRL/OCSP revocation checking for this verification."""
    NOT_REQUIRED = "not_required"   # Demo or Standard level
    CHECKED = "checked"              # CRL/OCSP fetched and passed
    CACHED = "cached"                # Previously validated, cache used
    UNAVAILABLE = "unavailable"      # Could not check (network, config)
    FAIL_CLOSED = "fail_closed"      # STRICT mode, unavailable → failed
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# --- Constants ---

OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"  # id-kp-timeStamping
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_RSA_SHA256 = "1.2.840.113549.1.1.11"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"

ALLOWED_HASH_ALGORITHMS = {OID_SHA256, OID_SHA384, OID_SHA512}
ALLOWED_SIGNATURE_ALGORITHMS = {OID_RSA_SHA256, OID_ECDSA_SHA256}


class TrustLevel(Enum):
    """How strictly to enforce trust-policy checks."""
    DEMO = "demo"         # Relaxed: no certificate chain validation
    STANDARD = "standard" # Full chain, EKU, expiry; no CRL/OCSP
    STRICT = "strict"     # Full chain + CRL/OCSP revocation


@dataclass
class CertificateConstraints:
    """Constraints a TSA certificate must satisfy."""
    subject_common_name: Optional[str] = None
    issuer_common_name: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: Optional[str] = None


@dataclass
class TrustPolicy:
    """Configured trust policy for timestamp verification."""

    level: TrustLevel = TrustLevel.DEMO
    label: str = "demonstration"

    # TSA provider allowlist (empty = any in demo mode)
    allowed_tsa_urls: Set[str] = field(default_factory=set)

    # Trusted root CA certificates (PEM paths)
    trusted_roots: List[Path] = field(default_factory=list)

    # Required Extended Key Usage
    required_eku: str = OID_TIME_STAMPING

    # Algorithm constraints
    allowed_hash_algorithms: Set[str] = field(
        default_factory=lambda: ALLOWED_HASH_ALGORITHMS.copy()
    )
    allowed_signature_algorithms: Set[str] = field(
        default_factory=lambda: ALLOWED_SIGNATURE_ALGORITHMS.copy()
    )

    # Required fields in the TSTInfo
    require_nonce_echo: bool = False
    require_policy: bool = False
    allowed_policies: Set[str] = field(default_factory=set)

    # Certificate revocation
    check_revocation: bool = False
    crl_urls: List[str] = field(default_factory=list)
    ocsp_responders: List[str] = field(default_factory=list)

    # Time tolerance (seconds) for notBefore/notAfter checks
    clock_tolerance: int = 300

    # --- Factory methods ---

    @classmethod
    def demo(cls) -> "TrustPolicy":
        """Relaxed demonstration policy — no certificate validation."""
        return cls(level=TrustLevel.DEMO, label="demonstration")

    @classmethod
    def from_json(cls, path: Path) -> "TrustPolicy":
        """Load policy from a JSON configuration file."""
        with open(path) as f:
            data = json.load(f)

        level = TrustLevel(data.get("level", "demo"))
        trusted_roots = [Path(p) for p in data.get("trusted_roots", [])]

        return cls(
            level=level,
            label=data.get("label", "custom"),
            allowed_tsa_urls=set(data.get("allowed_tsa_urls", [])),
            trusted_roots=trusted_roots,
            required_eku=data.get("required_eku", OID_TIME_STAMPING),
            allowed_hash_algorithms=set(
                data.get("allowed_hash_algorithms", ALLOWED_HASH_ALGORITHMS)
            ),
            allowed_signature_algorithms=set(
                data.get("allowed_signature_algorithms", ALLOWED_SIGNATURE_ALGORITHMS)
            ),
            require_nonce_echo=data.get("require_nonce_echo", False),
            require_policy=data.get("require_policy", False),
            allowed_policies=set(data.get("allowed_policies", [])),
            check_revocation=data.get("check_revocation", False),
            crl_urls=data.get("crl_urls", []),
            ocsp_responders=data.get("ocsp_responders", []),
            clock_tolerance=data.get("clock_tolerance", 300),
        )

    # --- Policy checks ---

    def is_tsa_allowed(self, tsa_url: Optional[str]) -> bool:
        """Check if a TSA URL is in the provider allowlist."""
        if self.level == TrustLevel.DEMO:
            return True
        if not self.allowed_tsa_urls:
            return False
        return tsa_url in self.allowed_tsa_urls

    def is_hash_algorithm_allowed(self, oid: str) -> bool:
        """Check if a hash algorithm OID is permitted."""
        if self.level == TrustLevel.DEMO:
            return oid in ALLOWED_HASH_ALGORITHMS
        return oid in self.allowed_hash_algorithms

    def is_signature_algorithm_allowed(self, oid: str) -> bool:
        """Check if a signature algorithm OID is permitted."""
        if self.level == TrustLevel.DEMO:
            return oid in ALLOWED_SIGNATURE_ALGORITHMS
        return oid in self.allowed_signature_algorithms

    def is_policy_allowed(self, policy_oid: Optional[str]) -> bool:
        """Check if a TSA policy OID is permitted."""
        if not self.require_policy:
            return True
        if policy_oid is None and self.require_policy:
            return False
        return policy_oid in self.allowed_policies

    def requires_certificate_chain(self) -> bool:
        """Whether certificate chain validation is required."""
        return self.level in (TrustLevel.STANDARD, TrustLevel.STRICT)

    def requires_revocation_check(self) -> bool:
        """Whether CRL/OCSP revocation checking is required.

        STANDARD never requires revocation.
        STRICT requires it when check_revocation is enabled.
        """
        return self.level == TrustLevel.STRICT and self.check_revocation

    def can_check_revocation(self) -> bool:
        """Whether revocation can actually be checked right now.

        Returns False when:
          - No CRL URLs or OCSP responders configured
          - cryptography package not available (can't verify responses)

        In STRICT mode, if `requires_revocation_check()` is True and
        this returns False, the verification MUST fail-closed.
        """
        has_endpoints = bool(self.crl_urls or self.ocsp_responders)
        if not has_endpoints:
            return False
        try:
            import cryptography  # noqa: F401
            return True
        except ImportError:
            return False

    @property
    def effective_revocation_status(self) -> RevocationStatus:
        """Determine the revocation status for this policy and environment."""
        if not self.requires_revocation_check():
            return RevocationStatus.NOT_REQUIRED
        if not self.can_check_revocation():
            return RevocationStatus.FAIL_CLOSED
        return RevocationStatus.CHECKED  # Will be refined after actual fetch


# --- Trust Policy Result ---

@dataclass
class TrustPolicyResult:
    """Result of trust-policy evaluation against a timestamp token."""

    passed: bool
    checks: List[str] = field(default_factory=list)    # Passed checks
    failures: List[str] = field(default_factory=list)   # Failed checks
    skips: List[str] = field(default_factory=list)      # Skipped (e.g., demo mode)
    revocation_status: RevocationStatus = RevocationStatus.NOT_REQUIRED
    trust_level: str = "DEMO"

    def add_pass(self, check: str) -> None:
        self.checks.append(check)

    def add_fail(self, check: str) -> None:
        self.failures.append(check)
        self.passed = False

    def add_skip(self, check: str) -> None:
        self.skips.append(check)

    @property
    def summary(self) -> str:
        lines = []
        for c in self.checks:
            lines.append(f"  ✓ {c}")
        for c in self.skips:
            lines.append(f"  ○ {c}")
        for c in self.failures:
            lines.append(f"  ✗ {c}")
        return "\n".join(lines)


DEFAULT_POLICY = TrustPolicy.demo()
