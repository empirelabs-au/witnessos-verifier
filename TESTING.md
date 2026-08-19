# Testing Policy

This document defines the project's policy for automated tests: **when** they
are run, **what** they cover, and **how** they must be extended for changes to
the codebase. It is a normative part of the contribution process (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

## When tests are run

- **Locally** — every contributor MUST run the full suite before opening a
  pull request:
  ```bash
  pip install -e ".[dev]"
  pytest tests/ -v
  ```
- **Continuously (CI)** — the full suite runs automatically on every push to
  `main` and on every pull request via the `CI` workflow
  (`.github/workflows/ci.yml`). CI installs the package into a fresh virtual
  environment and runs `pytest --cov=witnessos_verifier`. A pull request that
  fails CI cannot be merged.
- **Before every release** — the maintainers run the suite on the tagged
  commit, and the `Release` workflow builds the artifacts from that exact
  commit.

## Test suite layout

- `tests/` — offline tests for all verification logic: event loading,
  canonical hashing, signature verification, Merkle proofs, manifest checks,
  RFC 3161 timestamp validation, WORM integrity, and grade derivation.
- `fixtures/` — sanitised, self-contained evidence bundles used as test input
  (for example `fixtures/e4-gmail-approved-send/` and
  `fixtures/e4-stripe-refund/`). Fixtures never contain real credentials or
  live-service data.
- Tests are deliberately **offline** — no network access is required.

## Policy: major changes MUST add or update automated tests

Any change that alters behaviour of the software produced by this project is a
**major change** and MUST include tests in the same pull request:

- New or changed verification logic (signature, hashing, chain, ledger,
  manifest, timestamp, WORM, grade derivation) — MUST add tests covering the
  new behaviour, including at least one negative case (a crafted input that
  must be rejected).
- New or changed CLI options or output formats — MUST add or update tests that
  exercise the CLI entry point.
- New or changed parsing of evidence bundle fields — MUST add tests for valid
  input, malformed input, and boundary cases.
- New or changed trust-policy behaviour — MUST add tests for both the allowed
  and the denied policy paths.

Changes that are purely editorial (documentation, comments, formatting) do not
require new tests, but the existing suite MUST still pass.

## Code coverage

CI enforces a coverage report. Pull requests that introduce a significant drop
in coverage (as judged by the maintainers against the CI report) are not
merged until the gap is closed with tests.

## Reviewing the results

CI reports per-test results plus a coverage summary. A passing run means:

1. Every test in `tests/` passed in a clean environment.
2. The CLI entry point loads (`witnessos-verifier --version`).
3. Coverage was reported so maintainers can judge whether new code is tested.

If a test fails, fix the code or the test — never weaken or delete a failing
test to make CI pass without a maintainer review.
