"""WitnessOS Verifier — CLI.

Usage:
    witnessos-verifier verify ./evidence-bundle/
    witnessos-verifier --version
"""

import sys
from pathlib import Path

import click

from . import __version__
from .verifier import verify, VerifyError


@click.group()
@click.version_option(version=__version__, prog_name="witnessos-verifier")
def main():
    """WitnessOS™ Verifier — Independently verify AI action evidence bundles.

    This verifier reads WitnessOS evidence bundles and cryptographically
    verifies: canonical JSON, Ed25519 signatures, hash chains, Merkle proofs,
    RFC 3161 timestamps, and WORM evidence copies.

    No gateway, credential broker, or key management code is included.
    """
    pass


@main.command()
@click.argument("bundle_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
@click.option("--quiet", "-q", is_flag=True, help="Only print PASS/FAIL")
@click.option("--alpha", "alpha_mode", is_flag=True, help="Alpha mode: cap max evidence grade at E3")
def verify_cmd(bundle_path: Path, output_json: bool, quiet: bool, alpha_mode: bool = False):
    """Verify a WitnessOS evidence bundle.

    BUNDLE_PATH: Path to the evidence bundle directory containing
    events/, keys.json, case_manifest.json, batch_manifest.json,
    timestamp/, and worm/.
    """
    try:
        result = verify(bundle_path, alpha_mode=alpha_mode)
    except VerifyError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)

    if output_json:
        import json
        output = {
            "valid": result.valid,
            "grade": result.evidence_grade,
            "events": len(result.events),
            "chain_valid": result.chain_result.valid if result.chain_result else None,
            "ledger_valid": result.ledger_result.sequence_monotonic if result.ledger_result else None,
            "manifest_valid": result.manifest_result.valid if result.manifest_result else None,
            "timestamp_valid": result.timestamp_result.valid if result.timestamp_result else None,
            "worm_valid": result.worm_result.valid if result.worm_result else None,
            "errors": result.errors,
            "warnings": result.warnings,
        }
        click.echo(json.dumps(output, indent=2))
    elif quiet:
        if result.valid:
            click.echo("PASS")
        else:
            click.echo("FAIL")
            for err in result.errors:
                click.echo(f"  {err}", err=True)
    else:
        click.echo(result.summary())

        if result.warnings:
            click.echo(f"\nWarnings ({len(result.warnings)}):")
            for w in result.warnings:
                click.echo(f"  ⚠ {w}")

        if result.grade:
            click.echo(f"\nRequirements met:")
            for req in result.grade.requirements_met:
                click.echo(f"  ✓ {req}")
            if result.grade.requirements_missing:
                click.echo(f"Requirements not met:")
                for req in result.grade.requirements_missing:
                    click.echo(f"  ✗ {req}")

    # Exit code: 0 if valid, 1 if invalid
    sys.exit(0 if result.valid else 1)


if __name__ == "__main__":
    main()
