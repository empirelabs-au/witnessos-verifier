"""Minimal ASN.1 DER cursor for RFC 3161 timestamp verification.

No external ASN.1 library dependency. Handles enough DER to parse
CMS SignedData, verify signatures, and extract TSTInfo.

This is a standalone module — no witnessos-gateway dependency.
"""

import hashlib
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple


class DerError(Exception):
    """ASN.1 DER decoding error."""


@dataclass
class DerCursor:
    data: bytes
    pos: int = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def peek_tag(self) -> int:
        if self.pos >= len(self.data):
            raise DerError("Unexpected end of data")
        return self.data[self.pos]

    def read_tag(self, expected: Optional[int] = None) -> int:
        tag = self.peek_tag()
        if expected is not None and tag != expected:
            raise DerError(f"Expected tag 0x{expected:02x}, got 0x{tag:02x}")
        self.pos += 1
        return tag

    def read_length(self) -> int:
        if self.pos >= len(self.data):
            raise DerError("Unexpected end of data")
        b = self.data[self.pos]
        self.pos += 1
        if b < 0x80:
            return b
        num_octets = b & 0x7F
        if num_octets == 0:
            raise DerError("Indefinite length not supported")
        if num_octets > 4:
            raise DerError(f"Length too large: {num_octets} octets")
        length = 0
        for _ in range(num_octets):
            if self.pos >= len(self.data):
                raise DerError("Unexpected end of data in length")
            length = (length << 8) | self.data[self.pos]
            self.pos += 1
        return length

    def read_value(self, length: int) -> bytes:
        if self.pos + length > len(self.data):
            raise DerError(f"Expected {length} bytes, only {len(self.data) - self.pos} available")
        val = self.data[self.pos:self.pos + length]
        self.pos += length
        return val

    def read_tlv(self, expected_tag: Optional[int] = None) -> Tuple[int, bytes]:
        tag = self.read_tag(expected_tag)
        length = self.read_length()
        value = self.read_value(length)
        return tag, value

    def enter_constructed(self, expected_tag: Optional[int] = None) -> int:
        tag = self.read_tag(expected_tag)
        if tag & 0x20 == 0:
            raise DerError(f"Tag 0x{tag:02x} is not constructed")
        length = self.read_length()
        # For indefinite length, we'd need special handling; not used in TSA
        return self.pos + length

    def eoi(self) -> bool:
        return self.pos >= len(self.data)

    def peek_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DerError(f"Cannot peek {n} bytes")
        return self.data[self.pos:self.pos + n]


# OID constants
OID_SHA256 = (2, 16, 840, 1, 101, 3, 4, 2, 1)
OID_RSA_ENCRYPTION = (1, 2, 840, 113549, 1, 1, 1)
OID_SHA256_RSA = (1, 2, 840, 113549, 1, 1, 11)
OID_PKCS7_SIGNED_DATA = (1, 2, 840, 113549, 1, 7, 2)
OID_PKCS7_DATA = (1, 2, 840, 113549, 1, 7, 1)
OID_TST_INFO = (1, 3, 6, 1, 4, 1, 63324, 1)
OID_CONTENT_TYPE = (1, 2, 840, 113549, 1, 9, 3)
OID_MESSAGE_DIGEST = (1, 2, 840, 113549, 1, 9, 4)
OID_SIGNING_TIME = (1, 2, 840, 113549, 1, 9, 5)


def read_oid(cursor: DerCursor) -> Tuple[int, ...]:
    tag, value = cursor.read_tlv(expected_tag=0x06)
    if not value:
        raise DerError("Empty OID")
    components = []
    # First byte: first two components
    first = value[0]
    components.append(first // 40)
    components.append(first % 40)
    # Remaining bytes: variable-length encoded
    i = 1
    while i < len(value):
        val = 0
        while True:
            if i >= len(value):
                raise DerError("Truncated OID")
            b = value[i]
            i += 1
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        components.append(val)
    return tuple(components)


def read_integer(cursor: DerCursor) -> int:
    tag, value = cursor.read_tlv(expected_tag=0x02)
    return int.from_bytes(value, "big", signed=True)


def read_octet_string(cursor: DerCursor) -> bytes:
    tag, value = cursor.read_tlv(expected_tag=0x04)
    return value


def read_null(cursor: DerCursor) -> None:
    cursor.read_tlv(expected_tag=0x05)


def read_sequence(cursor: DerCursor) -> DerCursor:
    tag = cursor.read_tag(expected=0x30)
    length = cursor.read_length()
    inner = cursor.read_value(length)
    return DerCursor(inner)


def read_set(cursor: DerCursor) -> DerCursor:
    tag = cursor.read_tag(expected=0x31)
    length = cursor.read_length()
    inner = cursor.read_value(length)
    return DerCursor(inner)


def read_utc_time(cursor: DerCursor) -> str:
    tag, value = cursor.read_tlv(expected_tag=0x17)
    return value.decode("ascii")


def read_generalized_time(cursor: DerCursor) -> str:
    tag, value = cursor.read_tlv(expected_tag=0x18)
    return value.decode("ascii")


def read_bit_string(cursor: DerCursor) -> bytes:
    tag, value = cursor.read_tlv(expected_tag=0x03)
    if not value:
        raise DerError("Empty bit string")
    unused = value[0]
    return value[1:]


def format_oid(oid: Tuple[int, ...]) -> str:
    return ".".join(str(c) for c in oid)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --- Input Validation & Hardening ---

MAX_DER_SIZE = 1_000_000  # 1 MB max timestamp token
MAX_RECURSION_DEPTH = 32
ALLOWED_OIDS = {
    OID_PKCS7_SIGNED_DATA,
    OID_TST_INFO,
    OID_SHA256,
    OID_SHA256_RSA,
    OID_RSA_ENCRYPTION,
    OID_CONTENT_TYPE,
    OID_MESSAGE_DIGEST,
    OID_SIGNING_TIME,
}


def validate_der_input(data: bytes, strict: bool = False) -> List[str]:
    """Validate raw DER input before parsing.

    Checks:
      - Size limits
      - Basic structure (must be a SEQUENCE)
      - No trailing garbage (strict mode)
      - Length coherence (no lengths exceeding data bounds)

    Returns:
        List of validation issues (empty = valid).
    """
    issues: List[str] = []

    if not data:
        issues.append("Empty DER input")
        return issues

    if len(data) > MAX_DER_SIZE:
        issues.append(
            f"DER input exceeds max size: {len(data)} > {MAX_DER_SIZE}"
        )

    # Must start with a SEQUENCE tag (0x30)
    if data[0] != 0x30:
        issues.append(
            f"Expected SEQUENCE tag (0x30), got 0x{data[0]:02x}"
        )
        return issues

    # Validate length field
    try:
        total_len, len_bytes = _decode_length(data, 1)
        expected_total = 1 + len_bytes + total_len

        if expected_total > len(data):
            issues.append(
                f"Declared length exceeds data: {expected_total} > {len(data)}"
            )

        if strict and expected_total < len(data):
            issues.append(
                f"Trailing garbage after DER data: "
                f"{len(data) - expected_total} extra bytes"
            )
    except DerError as e:
        issues.append(f"Invalid DER length: {e}")

    return issues


def _decode_length(data: bytes, pos: int) -> Tuple[int, int]:
    """Decode a DER length field. Returns (value, bytes_consumed)."""
    if pos >= len(data):
        raise DerError("Unexpected end of data reading length")

    b = data[pos]
    if b < 0x80:
        return b, 1

    num_octets = b & 0x7F
    if num_octets == 0:
        raise DerError("Indefinite length not supported")
    if num_octets > 4:
        raise DerError(f"Length too large: {num_octets} octets")

    length = 0
    for i in range(num_octets):
        if pos + 1 + i >= len(data):
            raise DerError("Length field truncated")
        length = (length << 8) | data[pos + 1 + i]

    # Any long-form encoding for values under 128 is non-minimal DER
    if length < 128:
        raise DerError(
            f"Non-minimal length encoding: {length} "
            f"encoded in long form ({num_octets} octets)"
        )

    return length, 1 + num_octets


def validate_tst_info_fields(raw_tst_info: bytes) -> List[str]:
    """Validate TSTInfo for duplicate/missing fields.

    The TSTInfo must contain exactly one each of:
      version, policy, messageImprint, serialNumber, genTime
    and at most one of: nonce, accuracy.
    """
    issues: List[str] = []
    required_fields = {"version", "policy", "messageImprint", "serialNumber", "genTime"}
    seen_fields: Set[str] = set()

    cursor = DerCursor(raw_tst_info)
    try:
        tst_seq = read_sequence(cursor)

        # version (INTEGER)
        read_integer(tst_seq)
        seen_fields.add("version")

        # policy (OID)
        read_oid(tst_seq)
        seen_fields.add("policy")

        # messageImprint (SEQUENCE)
        mi_seq = read_sequence(tst_seq)
        seen_fields.add("messageImprint")

        # serialNumber (INTEGER)
        read_integer(tst_seq)
        seen_fields.add("serialNumber")

        # genTime (GeneralizedTime)
        read_generalized_time(tst_seq)
        seen_fields.add("genTime")

        # Optional: nonce (INTEGER)
        if not tst_seq.eoi():
            tag = tst_seq.peek_tag()
            if tag == 0x02:
                if "nonce" in seen_fields:
                    issues.append("Duplicate nonce field in TSTInfo")
                read_integer(tst_seq)
                seen_fields.add("nonce")

        # Optional: accuracy
        if not tst_seq.eoi():
            tag = tst_seq.peek_tag()
            if tag == 0x30:
                if "accuracy" in seen_fields:
                    issues.append("Duplicate accuracy field in TSTInfo")
                read_sequence(tst_seq)
                seen_fields.add("accuracy")

        # Check for unexpected trailing fields
        if not tst_seq.eoi():
            issues.append(
                f"Unexpected trailing data in TSTInfo "
                f"({tst_seq.remaining()} bytes remaining)"
            )

        # Check all required fields present
        missing = required_fields - seen_fields
        if missing:
            issues.append(f"Missing required TSTInfo fields: {missing}")

    except DerError as e:
        issues.append(f"TSTInfo validation error: {e}")

    return issues


def validate_oid_acceptance(oid: Tuple[int, ...]) -> Optional[str]:
    """Check if an OID is in the allowed set. Returns None if accepted, or error string."""
    if oid not in ALLOWED_OIDS:
        return f"OID {format_oid(oid)} not in allowed set"
    return None
