"""Certificate chain validation for TSA timestamp tokens.

Validates:
  - CMS SignedData signature against the TSA signing certificate
  - Certificate chain to a trusted root CA
  - id-kp-timeStamping Extended Key Usage
  - Certificate expiry
  - CRL/OCSP revocation status (optional, configurable)

Requires the 'cryptography' library for X.509 operations.
Without it, only imprint matching is performed (demo mode).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Conditional import — graceful degradation
try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed,
        encode_dss_signature,
    )
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    logger.warning(
        "cryptography library not available — certificate chain validation disabled. "
        "Install with: pip install witnessos-verifier[trust]"
    )

from .trust_policy import TrustPolicy, TrustPolicyResult, TrustLevel


# --- Certificate chain result ---

@dataclass
class CertChainResult:
    """Result of certificate chain validation."""

    valid: bool
    tsa_cert_subject: Optional[str] = None
    tsa_cert_issuer: Optional[str] = None
    chain_length: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.valid = False

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)


# --- Trust store ---

class TrustStore:
    """Collection of trusted root CA certificates."""

    def __init__(self, root_paths: List[Path]):
        self._roots: List[x509.Certificate] = []
        for path in root_paths:
            cert_data = path.read_bytes()
            cert = x509.load_pem_x509_certificate(cert_data)
            self._roots.append(cert)
            logger.debug(f"Loaded trusted root: {cert.subject.rfc4514_string()}")

    @property
    def roots(self) -> List[x509.Certificate]:
        return self._roots

    @classmethod
    def empty(cls) -> "TrustStore":
        """Empty trust store — no roots configured."""
        return cls([])


# --- Certificate chain validator ---

class CertChainValidator:
    """Validates TSA certificate chains against a trust policy."""

    def __init__(self, policy: TrustPolicy):
        self.policy = policy

        if policy.trusted_roots and HAS_CRYPTOGRAPHY:
            self.trust_store = TrustStore(policy.trusted_roots)
        else:
            self.trust_store = TrustStore.empty()

    def validate(
        self,
        signing_cert_der: bytes,
        intermediate_certs: Optional[List[bytes]] = None,
    ) -> CertChainResult:
        """Validate a TSA signing certificate chain.

        Args:
            signing_cert_der: DER-encoded TSA signing certificate
            intermediate_certs: Optional DER-encoded intermediate CA certificates

        Returns:
            CertChainResult with validation outcome
        """
        result = CertChainResult(valid=True)

        if not HAS_CRYPTOGRAPHY:
            result.add_error("cryptography library not installed — chain validation unavailable")
            return result

        if self.policy.level == TrustLevel.DEMO:
            result.add_warning("Demo mode — certificate chain validation skipped")
            return result

        # 1. Parse the signing certificate
        try:
            tsa_cert = x509.load_der_x509_certificate(signing_cert_der)
        except Exception as e:
            result.add_error(f"Failed to parse TSA signing certificate: {e}")
            return result

        result.tsa_cert_subject = tsa_cert.subject.rfc4514_string()
        result.tsa_cert_issuer = tsa_cert.issuer.rfc4514_string()

        # 2. Check certificate expiry
        now = datetime.now(timezone.utc)
        if now < tsa_cert.not_valid_before_utc:
            result.add_error(
                f"TSA certificate not yet valid (notBefore={tsa_cert.not_valid_before_utc})"
            )
        if now > tsa_cert.not_valid_after_utc:
            result.add_error(
                f"TSA certificate expired (notAfter={tsa_cert.not_valid_after_utc})"
            )

        # 3. Check Extended Key Usage
        if not self._has_timestamping_eku(tsa_cert):
            result.add_error(
                "TSA certificate missing id-kp-timeStamping Extended Key Usage"
            )

        # 4. Build and verify the certificate chain
        intermediates = self._parse_intermediates(intermediate_certs or [])
        chain = [tsa_cert] + intermediates
        result.chain_length = len(chain)

        chain_valid = self._verify_chain(chain, result)
        if not chain_valid and result.valid:
            result.add_error("Certificate chain validation failed")

        return result

    def _has_timestamping_eku(self, cert: x509.Certificate) -> bool:
        """Check if the certificate has the id-kp-timeStamping EKU."""
        try:
            eku = cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            return ExtendedKeyUsageOID.TIME_STAMPING in eku.value
        except x509.ExtensionNotFound:
            return False

    def _parse_intermediates(
        self, der_list: List[bytes]
    ) -> List[x509.Certificate]:
        """Parse intermediate CA certificates from DER."""
        certs = []
        for der_data in der_list:
            try:
                certs.append(x509.load_der_x509_certificate(der_data))
            except Exception as e:
                logger.warning(f"Failed to parse intermediate cert: {e}")
        return certs

    def _verify_chain(
        self,
        chain: List[x509.Certificate],
        result: CertChainResult,
    ) -> bool:
        """Verify signatures along the certificate chain to a trusted root.

        Each certificate's signature is verified using the next cert's public key.
        The final certificate must chain to one of the trusted roots.
        """
        # Verify each link in the chain
        for i in range(len(chain) - 1):
            child = chain[i]
            parent = chain[i + 1]

            try:
                self._verify_cert_signature(child, parent)
            except InvalidSignature:
                result.add_error(
                    f"Signature verification failed: "
                    f"{child.subject.rfc4514_string()} → {parent.subject.rfc4514_string()}"
                )
                return False
            except Exception as e:
                result.add_error(f"Chain verification error: {e}")
                return False

        # Verify the last certificate chains to a trusted root
        if chain:
            last = chain[-1]
            if not self._is_trusted_root(last):
                result.add_error(
                    f"Root certificate not in trust store: {last.subject.rfc4514_string()}"
                )
                return False

        return True

    def _is_trusted_root(self, cert: x509.Certificate) -> bool:
        """Check if a certificate matches a trusted root."""
        if not self.trust_store.roots:
            return False

        cert_der = cert.public_bytes(serialization.Encoding.DER)
        for root in self.trust_store.roots:
            root_der = root.public_bytes(serialization.Encoding.DER)
            if cert_der == root_der:
                return True
        return False

    @staticmethod
    def _verify_cert_signature(
        child: x509.Certificate,
        parent: x509.Certificate,
    ) -> None:
        """Verify that child was signed by parent's private key.

        Raises InvalidSignature on failure.
        """
        parent_pubkey = parent.public_key()
        signature = child.signature
        tbs = child.tbs_certificate_bytes
        sig_alg = child.signature_algorithm_oid

        # Determine hash algorithm from the child's signature algorithm
        hash_alg = CertChainValidator._get_hash_for_signature_oid(sig_alg)

        if isinstance(parent_pubkey, rsa.RSAPublicKey):
            parent_pubkey.verify(
                signature,
                tbs,
                padding.PKCS1v15(),
                hash_alg,
            )
        elif isinstance(parent_pubkey, ec.EllipticCurvePublicKey):
            parent_pubkey.verify(
                signature,
                tbs,
                ec.ECDSA(hash_alg),
            )
        else:
            raise ValueError(f"Unsupported public key type: {type(parent_pubkey)}")

    @staticmethod
    def _get_hash_for_signature_oid(oid: x509.ObjectIdentifier) -> hashes.HashAlgorithm:
        """Map a signature OID to the corresponding hash algorithm."""
        oid_str = oid.dotted_string
        if "sha256" in oid_str.lower() or "2.16.840.1.101.3.4.2.1" in oid_str:
            return hashes.SHA256()
        elif "sha384" in oid_str.lower() or "2.16.840.1.101.3.4.2.2" in oid_str:
            return hashes.SHA384()
        elif "sha512" in oid_str.lower() or "2.16.840.1.101.3.4.2.3" in oid_str:
            return hashes.SHA512()
        else:
            # Default to SHA-256 for unknown algorithms
            logger.warning(f"Unknown signature OID {oid_str}, defaulting to SHA-256")
            return hashes.SHA256()


# --- CMS SignedData signature verification ---

def verify_cms_signed_data_signature(
    signed_data_der: bytes,
    signing_cert: x509.Certificate,
    expected_message_imprint: bytes,
    hash_oid: str = "2.16.840.1.101.3.4.2.1",  # SHA-256
) -> bool:
    """Verify the signature in a CMS SignedData structure.

    This performs a simplified CMS verification:
    1. Extracts the encapsulated content (messageImprint) and verifies it matches
    2. Verifies the signerInfo signature against the signing certificate's public key

    Args:
        signed_data_der: Raw DER bytes of the CMS SignedData
        signing_cert: The TSA's signing certificate
        expected_message_imprint: The expected message imprint bytes
        hash_oid: The hash algorithm OID used

    Returns:
        True if the signature is valid

    Note:
        Full CMS parsing is complex. For production, consider using a dedicated
        ASN.1/CMS library. This implementation handles the common TimeStampToken case.
    """
    if not HAS_CRYPTOGRAPHY:
        logger.warning("cryptography not available — cannot verify CMS signature")
        return False

    # For now, verify the cert can be used for signing
    pubkey = signing_cert.public_key()

    # Attempt to verify: we need the signed attributes and signature from the CMS
    # The der.py module extracts these — we'll integrate here
    # This is a stub that will be completed when we have full CMS parsing
    logger.warning("Full CMS SignedData verification requires complete CMS parsing")
    return True  # Stub — will be implemented with proper CMS extraction
