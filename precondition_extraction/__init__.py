"""precondition_extraction — pulling structured CPE/precondition data out of CVE and GHSA text.

* ``extractor`` — the first-pass, regex/keyword extractor.
* ``schema`` — loads and validates fixtures against ``tests/fixtures/schema.json``.
* ``verifier`` — the second-pass Claude review of extractor candidates (optional
  ``verify`` extra).
"""
from __future__ import annotations

from .extractor import (
    ExtractionResult,
    PreconditionCandidate,
    VersionRange,
    extract,
    extract_precondition_candidates,
    extract_version_range,
)
from .schema import FixtureError, iter_fixtures, load_fixture, load_schema, validate_fixture
from .verifier import CandidateVerdict, VerificationError, verify_candidates

__all__ = [
    "VersionRange",
    "PreconditionCandidate",
    "ExtractionResult",
    "extract",
    "extract_version_range",
    "extract_precondition_candidates",
    "FixtureError",
    "load_schema",
    "load_fixture",
    "iter_fixtures",
    "validate_fixture",
    "CandidateVerdict",
    "VerificationError",
    "verify_candidates",
]
