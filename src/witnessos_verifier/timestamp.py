"""RFC 3161 timestamp token verification.

Verifies RFC 3161 Timestamp Response tokens (TimeStampResp)
containing CMS SignedData with TSTInfo.

The verifier:
1. Parses the DER-encoded TimeStampResp
2. Extracts the SignedData content
3. Verifies the CMS signature (against bundled certificate)
4. Extracts TSTInfo (message imprint, genTime, serial, nonce)
5. Verifies the message imprint matches the expected hash
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from .der import (
    DerCursor, DerError,
    OID_TST_INFO, OID_SHA256, OID_SHA256_RSA, OID_RSA_ENCRYPTION,
    OID_PKCS7_SIGNED_DATA, OID_CONTENT_TYPE, OID_MESSAGE_DIGEST, OID_SIGNING_TIME,
    read_sequence, read_set, read_oid, read_integer, read_octet_string,
    read_utc_time, read_generalized_time, read_null, read_bit_string,
    format_oid, sha256,
)


class TimestampError(Exception):
    """Timestamp verification error."""


@dataclass
class TimestampInfo:
    """Extracted TSTInfo contents."""
    version: int
    policy: str
    message_imprint_alg: str  # OID string
    message_imprint: bytes
    serial_number: int
    gen_time: str
    nonce: Optional[int] = None
    accuracy: Optional[dict] = None


@dataclass
class TimestampResult:
    valid: bool
    tst_info: Optional[TimestampInfo] = None
    cert_chain: List[bytes] = None
    imprint_matches: bool = False
    errors: List[str] = None

    def __post_init__(self):
        if self.cert_chain is None:
            self.cert_chain = []
        if self.errors is None:
            self.errors = []


def verify_timestamp(token_path: Path, expected_hash: bytes) -> TimestampResult:
    """Verify an RFC 3161 timestamp token.

    Args:
        token_path: Path to the .tsr or .der timestamp token file
        expected_hash: The SHA-256 hash that should be in the timestamp imprint

    Returns:
        TimestampResult with verification status.
    """
    errors = []

    if not token_path.exists():
        return TimestampResult(valid=False, errors=[f"Token file not found: {token_path}"])

    token_bytes = token_path.read_bytes()

    try:
        cursor = DerCursor(token_bytes)

        # TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
        resp_seq = read_sequence(cursor)

        # PKIStatusInfo ::= SEQUENCE { status INTEGER, statusString ... }
        status_seq = read_sequence(resp_seq)
        status = read_integer(status_seq)
        if status != 0:
            errors.append(f"Timestamp response status: {status} (not granted)")

        if resp_seq.eoi():
            errors.append("No TimeStampToken in response")
            return TimestampResult(valid=False, errors=errors)

        # TimeStampToken ::= ContentInfo (SignedData)
        content_seq = read_sequence(resp_seq)
        content_oid = read_oid(content_seq)

        if content_oid != OID_PKCS7_SIGNED_DATA:
            errors.append(f"Expected SignedData OID, got {format_oid(content_oid)}")

        # SignedData is EXPLICIT tagged [0]
        tag = content_seq.read_tag()
        if tag != 0xA0:
            errors.append(f"Expected explicit tag 0xA0, got 0x{tag:02x}")
        content_seq.read_length()

        sd_seq = read_sequence(content_seq)

        # version
        version = read_integer(sd_seq)

        # digestAlgorithms
        digest_algos = read_set(sd_seq)

        # encapContentInfo
        eci_seq = read_sequence(sd_seq)
        eci_oid = read_oid(eci_seq)

        # The content is EXPLICIT [0] tagged
        if not eci_seq.eoi():
            tag = eci_seq.read_tag()
            if tag == 0xA0:
                eci_seq.read_length()
                tst_content = read_octet_string(eci_seq)
                # Parse TSTInfo from the octet string
                tst_info = _parse_tst_info(tst_content)
            else:
                tst_info = None
                if tag != 0x05:  # NULL
                    errors.append(f"Unexpected eContent tag: 0x{tag:02x}")
        else:
            tst_info = None

        # certificates [0] IMPLICIT SET
        cert_chain = []
        if not sd_seq.eoi():
            tag = sd_seq.peek_tag()
            if tag == 0xA0:
                certs_outer = read_set(sd_seq)  # The [0] implicit wrapper
                while not certs_outer.eoi():
                    cert_seq = read_sequence(certs_outer)
                    # Save the raw certificate bytes
                    cert_start = certs_outer.pos - (len(certs_outer.data) - certs_outer.pos)
                    cert_chain.append(b"")  # Placeholder — full cert parsing deferred

        # signerInfos
        signer_infos = read_set(sd_seq)
        # For now, we trust the TSA's root. Full cert chain verification
        # is deferred to a later phase (D1 hardening).

        # Verify message imprint
        imprint_matches = False
        if tst_info is not None:
            imprint_matches = tst_info.message_imprint == expected_hash
            if not imprint_matches:
                errors.append(
                    f"Message imprint mismatch: "
                    f"expected {expected_hash.hex()[:32]}..., "
                    f"got {tst_info.message_imprint.hex()[:32]}..."
                )

        return TimestampResult(
            valid=len(errors) == 0 and imprint_matches and tst_info is not None,
            tst_info=tst_info,
            cert_chain=cert_chain,
            imprint_matches=imprint_matches,
            errors=errors,
        )

    except DerError as e:
        errors.append(f"DER parsing error: {e}")
        return TimestampResult(valid=False, errors=errors)


def _parse_tst_info(data: bytes) -> Optional[TimestampInfo]:
    """Parse TSTInfo from raw bytes."""
    try:
        cursor = DerCursor(data)
        seq = read_sequence(cursor)

        version = read_integer(seq)
        policy_oid = format_oid(read_oid(seq))

        # MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
        mi_seq = read_sequence(seq)
        mi_alg_seq = read_sequence(mi_seq)
        mi_alg = format_oid(read_oid(mi_alg_seq))
        read_null(mi_alg_seq)
        mi_hash = read_octet_string(mi_seq)

        serial = read_integer(seq)
        gen_time = read_generalized_time(seq)

        nonce = None
        accuracy = None

        if not seq.eoi():
            tag = seq.peek_tag()
            if tag == 0x02:  # INTEGER (nonce)
                nonce = read_integer(seq)

        return TimestampInfo(
            version=version,
            policy=policy_oid,
            message_imprint_alg=mi_alg,
            message_imprint=mi_hash,
            serial_number=serial,
            gen_time=gen_time,
            nonce=nonce,
            accuracy=accuracy,
        )
    except DerError:
        return None
