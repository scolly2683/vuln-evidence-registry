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


def test_remediation_and_general_notes_accepted_when_valid():
    data = _minimal_valid_fixture()
    data["expected"]["remediation_notes"] = [
        {"category": "vendor_fix", "text": "Fixed in version 1.0."},
        {"category": "workaround", "text": "Disable the feature flag."},
    ]
    data["expected"]["general_notes"] = ["Describes the flaw mechanism."]
    validate_fixture(data)


def test_rejects_unknown_remediation_category():
    data = _minimal_valid_fixture()
    data["expected"]["remediation_notes"] = [{"category": "patch", "text": "Fixed."}]
    with pytest.raises(FixtureError, match="remediation_notes\\[0\\].category"):
        validate_fixture(data)


def test_rejects_remediation_note_without_text():
    data = _minimal_valid_fixture()
    data["expected"]["remediation_notes"] = [{"category": "vendor_fix", "text": "  "}]
    with pytest.raises(FixtureError, match="remediation_notes\\[0\\].text"):
        validate_fixture(data)


def test_rejects_non_string_general_note():
    data = _minimal_valid_fixture()
    data["expected"]["general_notes"] = [{"text": "not a plain string"}]
    with pytest.raises(FixtureError, match="general_notes\\[0\\]"):
        validate_fixture(data)


def test_hand_verification_reclassification_is_pinned():
    """Pins the 2026-08-30 hand review of extractor candidates.

    False matches were reclassified, not dropped: Log4Shell's two fix-history
    sentences became vendor_fix remediation_notes and its flaw-description
    opener a general_note; PyYAML's attacker-mechanism sentence became a
    general_note; Shellshock had no false matches, so it carries neither
    field — the fields are optional and absence is meaningful.
    """
    fixtures = {data["cve_id"]: data["expected"] for _, data in iter_fixtures(FIXTURES_DIR)}

    log4j = fixtures["CVE-2021-44228"]
    assert [n["category"] for n in log4j["remediation_notes"]] == ["vendor_fix", "vendor_fix"]
    assert "disabled by default" in log4j["remediation_notes"][0]["text"]
    assert "completely removed" in log4j["remediation_notes"][1]["text"]
    assert len(log4j["general_notes"]) == 1
    assert "JNDI features" in log4j["general_notes"][0]

    pyyaml = fixtures["CVE-2020-14343"]
    assert "remediation_notes" not in pyyaml
    assert len(pyyaml["general_notes"]) == 1
    assert "python/object/new constructor" in pyyaml["general_notes"][0]

    shellshock = fixtures["CVE-2014-6271"]
    assert "remediation_notes" not in shellshock
    assert "general_notes" not in shellshock


def _minimal_valid_fixture() -> dict:
    return {
        "cve_id": "CVE-2099-00001",
        "ghsa_id": None,
        "source": "nvd",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2099-00001",
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
