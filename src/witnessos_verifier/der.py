"""Minimal ASN.1 DER cursor for RFC 3161 timestamp verification.

No external ASN.1 library dependency. Handles enough DER to parse
CMS SignedData, verify signatures, and extract TSTInfo.

This is a standalone module — no witnessos-gateway dependency.
"""

import hashlib
from dataclasses import dataclass
from typing import Optional, Tuple


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
