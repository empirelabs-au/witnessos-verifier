"""WitnessOS Verifier — Standalone library for verifying WitnessOS evidence bundles.

This package contains NO gateway, credential broker, connector, policy engine,
or key management code. It is a pure verification client.
"""

__version__ = "0.1.0"
__all__ = ["verifier", "events", "signatures", "key_registry", "case_chain",
           "ledger", "merkle", "manifest", "timestamp", "worm", "grades", "der"]
