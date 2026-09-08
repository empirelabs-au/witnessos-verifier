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
    checks event signatures, hash chains, and signed batch/Merkle binding.
    E4 requires an operator trust policy, an authenticated RFC 3161 timestamp,
    and a signed receipt from an independently trusted retention custodian.

    No gateway, credential broker, or key management code is included.
    """
    pass


@main.command()
@click.argument("bundle_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
@click.option("--quiet", "-q", is_flag=True, help="Only print PASS/FAIL")
@click.option("--alpha", "alpha_mode", is_flag=True, help="Alpha mode: cap max evidence grade at E3")
@click.option('--trust-policy', type=click.Path(exists=True, dir_okay=False, path_type=Path), help='Operator policy outside the bundle')
@click.option('--tsa-url', help='Expected TSA URL from operator configuration')
@click.option('--expected-nonce', type=int, help='Nonce retained from the original timestamp request')
def verify_cmd(bundle_path: Path, output_json: bool, quiet: bool, alpha_mode: bool = False,
               trust_policy=None, tsa_url=None, expected_nonce=None):
    """Verify a WitnessOS evidence bundle.

    BUNDLE_PATH: Path to the evidence bundle directory containing
    events/, keys.json, case_manifest.json, batch_manifest.json,
    timestamp/, and worm/.
    """
    try:
        from .trust_policy import TrustPolicy
        if trust_policy and trust_policy.resolve().is_relative_to(bundle_path.resolve()):
            raise VerifyError('Trust policy must be provisioned outside the evidence bundle')
        policy = TrustPolicy.from_json(trust_policy) if trust_policy else None
        result = verify(bundle_path, alpha_mode=alpha_mode, trust_policy=policy,
                        tsa_url=tsa_url, expected_nonce=expected_nonce)
    except (VerifyError, ValueError, TypeError, OSError) as e:
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
            "timestamp_signature_verified": result.timestamp_result.signature_verified if result.timestamp_result else False,
            "timestamp_trust_verified": result.timestamp_result.trust_verified if result.timestamp_result else False,
            "retention_verified": result.worm_result.retention_verified if result.worm_result else False,
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
