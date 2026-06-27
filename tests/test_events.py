"""Test event loading and canonical hashing."""
import json
import hashlib
from pathlib import Path


class TestEventLoading:
    def test_loads_all_seven_events(self, events):
        assert len(events) == 7

    def test_events_have_sequential_ids(self, events):
        for i, evt in enumerate(events):
            assert evt.event_id == f"evt_sanitized_{i:04d}"

    def test_events_have_sequential_seqs(self, events):
        for i, evt in enumerate(events):
            assert evt.seq == 42 + i

    def test_events_have_valid_prev_hash_chain(self, events):
        for i in range(1, len(events)):
            expected = hashlib.sha256(events[i-1].canonical_bytes).hexdigest()
            assert events[i].prev_hash == expected, \
                f"Event {i} prev_hash does not match event {i-1} hash"

    def test_canonical_bytes_are_valid_json(self, events):
        for evt in events:
            data = json.loads(evt.canonical_bytes)
            assert data["event_id"] == evt.event_id

    def test_all_events_signed(self, events):
        for evt in events:
            assert evt.signed is not None
            assert evt.signed["signer_key_id"] == "key_sanitized_demo_001"
            assert evt.signed["algorithm"] == "Ed25519"


class TestBogusInput:
    def test_empty_dir(self, tmp_path):
        from witnessos_verifier.events import load_events, EventError
        (tmp_path / "bundle").mkdir()
        (tmp_path / "bundle" / "events").mkdir()
        try:
            load_events(tmp_path / "bundle")
        except EventError:
            pass
        else:
            assert False, "Should have raised EventError for empty events dir"

    def test_invalid_json(self, tmp_path):
        from witnessos_verifier.events import load_events, EventError
        (tmp_path / "bundle").mkdir()
        (tmp_path / "bundle" / "events").mkdir()
        (tmp_path / "bundle" / "events" / "bad.json").write_text("not json")
        try:
            load_events(tmp_path / "bundle")
        except EventError:
            pass
        else:
            assert False, "Should have raised EventError"

    def test_missing_fields(self, tmp_path):
        from witnessos_verifier.events import load_events, EventError
        (tmp_path / "bundle").mkdir()
        (tmp_path / "bundle" / "events").mkdir()
        (tmp_path / "bundle" / "events" / "incomplete.json").write_text('{"event_id": "x"}')
        try:
            load_events(tmp_path / "bundle")
        except EventError:
            pass
        else:
            assert False, "Should have raised EventError"
