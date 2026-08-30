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
    assert len(fixtures) == 13
    for path, data in fixtures:
        validate_fixture(data)


@pytest.mark.parametrize(
    "cve_id",
    [
        "CVE-2021-44228",
        "CVE-2014-6271",
        "CVE-2020-14343",
        "CVE-2018-7600",
        "CVE-2020-1472",
        "CVE-2014-0160",
        "CVE-2017-0144",
        "CVE-2016-5195",
        "CVE-2022-22965",
        "CVE-2021-3156",
        "CVE-2021-23337",
        "CVE-2020-26160",
        "CVE-2019-5418",
    ],
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


def test_empty_preconditions_list_is_a_valid_explicit_claim():
    # Deliberate rule change (was: rejected). An empty list is the explicit claim
    # "nothing gates applicability" (CVE-2018-7600) or "the advisory text states no
    # precondition" (CVE-2019-5418) — the fixture's notes must say which. Only a
    # missing or non-list value is invalid.
    data = _minimal_valid_fixture()
    data["expected"]["preconditions"] = []
    validate_fixture(data)


def test_rejects_non_list_preconditions():
    data = _minimal_valid_fixture()
    data["expected"]["preconditions"] = None
    with pytest.raises(FixtureError, match="preconditions must be a list"):
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


def test_second_batch_key_claims_are_pinned():
    """Pins the load-bearing claims of the 10 fixtures added 2026-08-30.

    The two empty precondition lists make OPPOSITE claims, distinguished in
    their notes: Drupalgeddon2 = genuinely nothing gates applicability;
    Rails CVE-2019-5418 = the advisory text states no precondition even
    though one truly exists (render file:) — the pinned limit of text-only
    extraction. jwt-go is the first real none_available remediation, and
    Spring4Shell's Tomcat/WAR condition is the model required_for_exploit:
    false case (the advisory hedges that other exploit paths may exist).
    """
    fixtures = {data["cve_id"]: data["expected"] for _, data in iter_fixtures(FIXTURES_DIR)}

    assert fixtures["CVE-2018-7600"]["preconditions"] == []
    assert fixtures["CVE-2019-5418"]["preconditions"] == []

    jwtgo = fixtures["CVE-2020-26160"]
    assert [n["category"] for n in jwtgo["remediation_notes"]] == ["none_available"]
    assert jwtgo["affected_versions"]["fixed"] is None

    spring = fixtures["CVE-2022-22965"]
    by_id = {p["id"]: p for p in spring["preconditions"]}
    assert by_id["jdk-9-or-newer"]["required_for_exploit"] is True
    assert by_id["jdk-9-or-newer"]["category"] == "platform"
    assert by_id["tomcat-war-deployment"]["required_for_exploit"] is False

    zerologon = fixtures["CVE-2020-1472"]
    assert [n["category"] for n in zerologon["remediation_notes"]] == ["vendor_fix"]

    ecosystems = {
        "CVE-2021-23337": "pkg:npm/lodash",
        "CVE-2020-26160": "pkg:golang/github.com/dgrijalva/jwt-go",
        "CVE-2019-5418": "pkg:gem/actionview",
    }
    for cve, purl in ecosystems.items():
        assert fixtures[cve]["identity"]["purl"] == purl


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
