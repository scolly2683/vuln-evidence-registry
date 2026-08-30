import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from precondition_extraction.schema import FixtureError, iter_fixtures, load_schema, validate_fixture

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_schema_loads():
    schema = load_schema()
    assert schema["title"] == "Precondition extraction fixture"


def test_all_shipped_fixtures_validate():
    fixtures = iter_fixtures(FIXTURES_DIR)
    assert len(fixtures) == 3
    for path, data in fixtures:
        validate_fixture(data)


@pytest.mark.parametrize(
    "cve_id",
    ["CVE-2021-44228", "CVE-2014-6271", "CVE-2020-14343"],
)
def test_expected_fixture_present(cve_id):
    names = {path.stem for path, _ in iter_fixtures(FIXTURES_DIR)}
    assert cve_id in names


def test_rejects_missing_top_level_field():
    data = {
        "cve_id": "CVE-2021-44228",
        "ghsa_id": None,
        "source": "nvd",
        "retrieved": "2026-08-30",
        # advisory_text missing
        "expected": {},
    }
    with pytest.raises(FixtureError, match="advisory_text"):
        validate_fixture(data)


def test_rejects_bad_cve_id_shape():
    data = _minimal_valid_fixture()
    data["cve_id"] = "not-a-cve"
    with pytest.raises(FixtureError, match="cve_id"):
        validate_fixture(data)


def test_rejects_unknown_precondition_category():
    data = _minimal_valid_fixture()
    data["expected"]["preconditions"][0]["category"] = "vibes"
    with pytest.raises(FixtureError, match="category"):
        validate_fixture(data)


def test_rejects_duplicate_precondition_ids():
    data = _minimal_valid_fixture()
    data["expected"]["preconditions"].append(dict(data["expected"]["preconditions"][0]))
    with pytest.raises(FixtureError, match="duplicates"):
        validate_fixture(data)


def test_rejects_empty_preconditions_list():
    data = _minimal_valid_fixture()
    data["expected"]["preconditions"] = []
    with pytest.raises(FixtureError, match="preconditions"):
        validate_fixture(data)


def _minimal_valid_fixture() -> dict:
    return {
        "cve_id": "CVE-2099-00001",
        "ghsa_id": None,
        "source": "nvd",
        "retrieved": "2026-08-30",
        "advisory_text": "Example advisory text.",
        "expected": {
            "identity": {
                "vendor": "Example Vendor",
                "product": "Example Product",
                "cpe": None,
                "purl": None,
            },
            "affected_versions": {
                "introduced": None,
                "fixed": "1.0",
                "excluded_fixed": [],
            },
            "preconditions": [
                {
                    "id": "example-condition",
                    "statement": "Some condition must hold.",
                    "category": "configuration",
                    "enabled_by_default": None,
                    "required_for_exploit": True,
                }
            ],
        },
    }
