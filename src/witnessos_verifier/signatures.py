"""Ed25519 signature verification for WitnessOS evidence.

Verifies detached Ed25519 signatures against canonical event data.
Uses PyNaCl for Ed25519 operations.
"""

import base64
import hashlib
from typing import Dict, Optional

import nacl.exceptions
import nacl.signing


class SignatureError(Exception):
    """Signature verification error."""


class KeyStatus:
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"

    @classmethod
    def valid_statuses(cls) -> set:
        return {cls.ACTIVE}


def verify_detached_signature(
    public_key_hex: str,
    message: bytes,
    signature_b64: str,
) -> bool:
    """Verify a detached Ed25519 signature.

    Args:
        public_key_hex: Ed25519 public key as hex string (64 hex chars = 32 bytes)
        message: The message that was signed (canonical bytes)
        signature_b64: Base64-encoded Ed25519 signature

    Returns:
        True if the signature is valid.
    """
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = base64.b64decode(signature_b64, validate=True)
        verify_key = nacl.signing.VerifyKey(public_key_bytes)
        verify_key.verify(message, signature_bytes)
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False


def verify_signed_field(
    event_data: dict,
    signature_key: str = "signed",
) -> Dict[str, str]:
    """Verify the 'signed' field of an event.

    The 'signed' field contains a copy of the headers + payload that was
    signed. This function verifies the canonical bytes match.

    Returns:
        Dict with 'status': 'ok' or 'mismatch', and details.
    """
    raise NotImplementedError("Full signed-field verification requires event context")
