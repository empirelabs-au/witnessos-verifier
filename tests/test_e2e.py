"""Test end-to-end verification of E4 fixture."""
import json
from pathlib import Path


class TestE2EVerification:
    def test_full_verification_passes(self, bundle_path):
        from witnessos_verifier.verifier import verify

        result = verify(bundle_path)
        assert result.valid, f"Verification failed: {result.errors}"
        assert result.grade.grade == "E4", f"Expected E4, got {result.grade.grade}"
        assert len(result.errors) == 0, f"Unexpected errors: {result.errors}"
        assert "E4: RFC 3161 timestamp valid" in result.grade.requirements_met
        assert "E4: WORM evidence copy valid" in result.grade.requirements_met

    def test_all_requirements_in_result(self, bundle_path):
        from witnessos_verifier.verifier import verify

        result = verify(bundle_path)
        required = [
            "E1: Events loaded",
            "E2: Case hash chain valid",
            "E2: Ledger sequence valid",
            "E2: Manifest signature valid",
            "E3: Provider acknowledged",
            "E4: RFC 3161 timestamp valid",
            "E4: WORM evidence copy valid",
        ]
        for req in required:
            assert req in result.grade.requirements_met, \
                f"Missing requirement: {req} (met: {result.grade.requirements_met})"

    def test_no_requirements_missing(self, bundle_path):
        from witnessos_verifier.verifier import verify

        result = verify(bundle_path)
        assert len(result.grade.requirements_missing) == 0, \
            f"Missing requirements: {result.grade.requirements_missing}"


class TestCLIVerify:
    def test_cli_verify_output(self, bundle_path):
        import subprocess

        exe = Path(__file__).parent.parent / ".venv" / "bin" / "witnessos-verifier"
        result = subprocess.run(
            [str(exe), "verify", str(bundle_path)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert "E4" in result.stdout


class TestEmptyBundle:
    def test_empty_bundle_graceful(self, tmp_path):
        from witnessos_verifier.verifier import verify

        (tmp_path / "empty").mkdir()
        result = verify(tmp_path / "empty")
        assert result.grade is None, f"Expected grade=None, got {result.grade}"
        assert "Events directory not found" in str(result.errors)
