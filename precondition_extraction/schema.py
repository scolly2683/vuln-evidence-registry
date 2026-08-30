"""Load and validate precondition-extraction fixtures against schema.json.

Not a general JSON Schema engine — a small, tailored checker for exactly the
shape ``tests/fixtures/schema.json`` describes. Values that must stay in
sync with real choices (``source``, precondition ``category``) are read out
of schema.json itself rather than duplicated here, so schema.json stays the
one place to add a new one.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

SCHEMA_PATH = Path(__file__).resolve().parent / "tests" / "fixtures" / "schema.json"

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_GHSA_ID_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


class FixtureError(Exception):
    """Raised when a fixture does not match schema.json."""


def load_schema(path: Path | str = SCHEMA_PATH) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _source_enum(schema: dict) -> list[str]:
    return schema["properties"]["source"]["enum"]


def _category_enum(schema: dict) -> list[str]:
    precond = schema["properties"]["expected"]["properties"]["preconditions"]
    return precond["items"]["properties"]["category"]["enum"]


def _remediation_category_enum(schema: dict) -> list[str]:
    notes = schema["properties"]["expected"]["properties"]["remediation_notes"]
    return notes["items"]["properties"]["category"]["enum"]


def validate_fixture(data: dict, schema: dict | None = None) -> None:
    """Raise FixtureError listing every problem found, or return None."""
    schema = schema if schema is not None else load_schema()
    errors: list[str] = []

    for key in ("cve_id", "ghsa_id", "source", "source_url", "retrieved", "advisory_text", "expected"):
        if key not in data:
            errors.append(f"missing top-level field: {key}")
    if errors:
        raise FixtureError("fixture invalid:\n  " + "\n  ".join(errors))

    if not _CVE_ID_RE.match(str(data["cve_id"])):
        errors.append(f"cve_id {data['cve_id']!r} does not look like CVE-YYYY-NNNN")
    if data["ghsa_id"] is not None and not _GHSA_ID_RE.match(str(data["ghsa_id"])):
        errors.append(f"ghsa_id {data['ghsa_id']!r} does not look like GHSA-xxxx-xxxx-xxxx")
    if data["source"] not in _source_enum(schema):
        errors.append(f"source {data['source']!r} must be one of {_source_enum(schema)}")
    if not str(data["source_url"]).startswith("https://"):
        errors.append(f"source_url {data['source_url']!r} must be an https:// URL")
    if not _DATE_RE.match(str(data["retrieved"])):
        errors.append(f"retrieved {data['retrieved']!r} must be an ISO date (YYYY-MM-DD)")
    if not str(data["advisory_text"]).strip():
        errors.append("advisory_text must not be empty")

    expected = data["expected"]
    for key in ("identity", "affected_versions", "preconditions"):
        if key not in expected:
            errors.append(f"expected.{key} is required")
    if errors:
        raise FixtureError("fixture invalid:\n  " + "\n  ".join(errors))

    identity = expected["identity"]
    for key in ("vendor", "product", "cpe", "purl"):
        if key not in identity:
            errors.append(f"expected.identity.{key} is required")
    if not identity.get("vendor"):
        errors.append("expected.identity.vendor must not be empty")
    if not identity.get("product"):
        errors.append("expected.identity.product must not be empty")

    versions = expected["affected_versions"]
    for key in ("introduced", "fixed", "excluded_fixed"):
        if key not in versions:
            errors.append(f"expected.affected_versions.{key} is required")
    if not isinstance(versions.get("excluded_fixed", []), list):
        errors.append("expected.affected_versions.excluded_fixed must be a list")

    preconditions = expected["preconditions"]
    # An EMPTY list is valid and meaningful: an explicit claim that nothing gates
    # applicability (or that the advisory text states no precondition — the fixture's
    # notes must say which). Only a missing/non-list value is an error.
    if not isinstance(preconditions, list):
        errors.append("expected.preconditions must be a list (empty = explicit no-preconditions claim)")
    else:
        categories = _category_enum(schema)
        seen_ids: set[str] = set()
        for i, cond in enumerate(preconditions):
            label = f"expected.preconditions[{i}]"
            for key in ("id", "statement", "category", "enabled_by_default", "required_for_exploit"):
                if key not in cond:
                    errors.append(f"{label}.{key} is required")
            cid = cond.get("id")
            if cid:
                if not _SLUG_RE.match(str(cid)):
                    errors.append(f"{label}.id {cid!r} must be a lowercase-hyphen slug")
                if cid in seen_ids:
                    errors.append(f"{label}.id {cid!r} duplicates another precondition in this fixture")
                seen_ids.add(cid)
            if cond.get("category") not in categories:
                errors.append(f"{label}.category {cond.get('category')!r} must be one of {categories}")
            if not isinstance(cond.get("required_for_exploit"), bool):
                errors.append(f"{label}.required_for_exploit must be true or false")
            if cond.get("enabled_by_default") not in (True, False, None):
                errors.append(f"{label}.enabled_by_default must be true, false, or null")

    # Optional CSAF-vocabulary fields — validated only when present.
    if "remediation_notes" in expected:
        remediation = expected["remediation_notes"]
        if not isinstance(remediation, list):
            errors.append("expected.remediation_notes must be a list")
        else:
            rem_categories = _remediation_category_enum(schema)
            for i, note in enumerate(remediation):
                label = f"expected.remediation_notes[{i}]"
                if not isinstance(note, dict):
                    errors.append(f"{label} must be an object with category and text")
                    continue
                if note.get("category") not in rem_categories:
                    errors.append(
                        f"{label}.category {note.get('category')!r} must be one of {rem_categories}"
                    )
                if not isinstance(note.get("text"), str) or not note["text"].strip():
                    errors.append(f"{label}.text must be a non-empty string")
    if "general_notes" in expected:
        general = expected["general_notes"]
        if not isinstance(general, list):
            errors.append("expected.general_notes must be a list")
        else:
            for i, note in enumerate(general):
                if not isinstance(note, str) or not note.strip():
                    errors.append(f"expected.general_notes[{i}] must be a non-empty string")

    if errors:
        raise FixtureError("fixture invalid:\n  " + "\n  ".join(errors))


def load_fixture(path: Path | str) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    validate_fixture(data)
    return data


def iter_fixtures(fixtures_dir: Path | str | None = None) -> list[tuple[Path, dict]]:
    directory = Path(fixtures_dir) if fixtures_dir else SCHEMA_PATH.parent
    return [
        (path, load_fixture(path))
        for path in sorted(directory.glob("CVE-*.yaml"))
    ]
