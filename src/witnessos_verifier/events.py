"""Event loading and canonical JSON hashing.

WitnessOS evidence bundles store events as deterministic JSON files.
Each event has a canonical serialisation that is hashed for chain integrity.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


class EventError(Exception):
    """Event loading or verification error."""


@dataclass
class Event:
    """A single event from an evidence bundle."""
    event_id: str
    event_type: str
    case_id: str
    seq: int
    prev_hash: str
    payload: Dict[str, Any]
    raw: bytes = field(repr=False, default=b"")
    signed: Optional[Dict[str, Any]] = None

    @property
    def canonical_bytes(self) -> bytes:
        """Canonical JSON serialisation for hashing."""
        obj = {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "case_id": self.case_id,
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "payload": self.payload,
        }
        if self.signed is not None:
            obj["signed"] = self.signed
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def canonical_hash(self) -> str:
        """SHA-256 of canonical bytes, hex-encoded."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @classmethod
    def from_file(cls, path: Path) -> "Event":
        """Load an event from a JSON file."""
        if not path.exists():
            raise EventError(f"Event file not found: {path}")
        raw = path.read_bytes()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise EventError(f"Invalid JSON in {path}: {e}") from e

        required = ["event_id", "event_type", "case_id", "seq", "prev_hash", "payload"]
        for field_name in required:
            if field_name not in data:
                raise EventError(f"Missing required field '{field_name}' in {path}")

        return cls(
            event_id=data["event_id"],
            event_type=data["event_type"],
            case_id=data["case_id"],
            seq=data["seq"],
            prev_hash=data["prev_hash"],
            payload=data["payload"],
            signed=data.get("signed"),
            raw=raw,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """Create an Event from a dictionary (for testing)."""
        return cls(
            event_id=data["event_id"],
            event_type=data["event_type"],
            case_id=data["case_id"],
            seq=data["seq"],
            prev_hash=data["prev_hash"],
            payload=data["payload"],
            signed=data.get("signed"),
            raw=json.dumps(data, sort_keys=True).encode("utf-8"),
        )


def load_events(bundle_dir: Path) -> List[Event]:
    """Load all events from an evidence bundle directory."""
    events_dir = bundle_dir / "events"
    if not events_dir.exists():
        raise EventError(f"Events directory not found: {events_dir}")

    event_files = sorted(events_dir.glob("*.json"))
    if not event_files:
        raise EventError(f"No event files in {events_dir}")

    events = []
    for f in event_files:
        events.append(Event.from_file(f))

    # Sort by sequence number
    events.sort(key=lambda e: e.seq)
    return events


def verify_event_hash(event: Event, expected_hash: str) -> bool:
    """Verify an event's canonical hash matches the expected value."""
    actual = event.canonical_hash
    return actual == expected_hash
