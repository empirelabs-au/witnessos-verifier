# WitnessOS Verifier
# Copyright (c) 2026 Empire Labs Pty Ltd
# SPDX-License-Identifier: Apache-2.0
# Source: https://github.com/empirelabs-au/witnessos-verifier
# Provenance: WOSV-2026-09-09-A7K2 (do not remove attribution)

"""Test fixtures for witnessos-verifier."""
import json
import pytest
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "e4-gmail-approved-send"


@pytest.fixture
def bundle_path():
    """Path to the E4 evidence bundle fixture."""
    path = FIXTURE_DIR
    assert path.exists(), f"Fixture not found: {path}"
    return path


@pytest.fixture
def key_registry(bundle_path):
    """KeyRegistry object loaded from fixture."""
    from witnessos_verifier.key_registry import KeyRegistry
    keys_data = json.loads((bundle_path / "keys.json").read_text())
    return KeyRegistry(keys_data)


@pytest.fixture
def events(bundle_path):
    """Loaded events from fixture."""
    from witnessos_verifier.events import load_events
    return load_events(bundle_path)
