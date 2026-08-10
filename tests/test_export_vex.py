"""tools/export_vex.py — the suppression registry as OpenVEX author.

Contract: every exported statement is spec-valid (status, justification
labels, products present); anything inexpressible is skipped loudly, never
mistranslated; and expired suppressions must not keep silencing scanners.
"""

import datetime as dt
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "export_vex", REPO_ROOT / "tools" / "export_vex.py"
)
vex_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vex_mod)

TODAY = dt.date(2026, 8, 9)


@pytest.fixture(scope="module")
def exported():
    return vex_mod.export(
        REPO_ROOT / "registry",
        author="test@example.org",
        doc_id="urn:vex:test:1",
        timestamp="2026-08-09T00:00:00Z",
        today=TODAY,
    )


def test_document_shape(exported):
    document, _ = exported
    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert document["author"] == "test@example.org"
    assert document["statements"], "seed suppressions should produce statements"


def test_seed_statements_are_spec_valid(exported):
    document, _ = exported
    for statement in document["statements"]:
        assert statement["vulnerability"]["name"].startswith("CVE-")
        assert statement["products"], "VEX statements are per CVE x product"
        assert statement["status"] in ("not_affected", "affected")
        if statement["status"] == "not_affected":
            assert statement["justification"] in vex_mod.VALID_JUSTIFICATIONS
        else:
            assert statement["action_statement"]


def test_log4j_seed_maps_to_vulnerable_code_not_present(exported):
    document, _ = exported
    by_cve = {s["vulnerability"]["name"]: s for s in document["statements"]}
    log4j = by_cve["CVE-2021-44228"]
    assert log4j["status"] == "not_affected"
    assert log4j["justification"] == "vulnerable_code_not_present"
    assert log4j["products"] == [{"@id": "pkg:maven/log4j/log4j"}]
    assert "JNDI" in log4j["impact_statement"]


def test_qid_only_rule_without_vex_block_is_skipped_loudly():
    statements, skipped = vex_mod.statements_for(
        {
            "id": "sup-x",
            "match": {"qid": ["12345"]},
            "verdict": "false_positive",
        }
    )
    assert statements == []
    assert "QID-only" in skipped


def test_missing_products_is_skipped_loudly():
    statements, skipped = vex_mod.statements_for(
        {
            "id": "sup-x",
            "match": {"cve_id": ["CVE-2020-0001"]},
            "verdict": "false_positive",
        }
    )
    assert statements == []
    assert "products" in skipped


def test_cve_from_match_when_vex_block_omits_it():
    statements, skipped = vex_mod.statements_for(
        {
            "id": "sup-x",
            "match": {"cve_id": ["CVE-2020-0001"]},
            "verdict": "false_positive",
            "vex": {"products": ["pkg:npm/foo"]},
        }
    )
    assert skipped is None
    assert statements[0]["vulnerability"]["name"] == "CVE-2020-0001"
    assert statements[0]["justification"] == "component_not_present"  # verdict default


def test_risk_accepted_maps_to_affected_with_action_statement():
    statements, skipped = vex_mod.statements_for(
        {
            "id": "sup-ra",
            "match": {"cve_id": ["CVE-2020-0002"]},
            "verdict": "risk_accepted",
            "review_by": "2027-01-01",
            "vex": {"products": ["pkg:npm/foo"]},
        }
    )
    assert skipped is None
    assert statements[0]["status"] == "affected"
    assert "2027-01-01" in statements[0]["action_statement"]
    assert "justification" not in statements[0]


def test_invalid_justification_fails_loudly():
    with pytest.raises(vex_mod.VexExportError, match="not an\\s+OpenVEX label"):
        vex_mod.statements_for(
            {
                "id": "sup-x",
                "match": {"cve_id": ["CVE-2020-0003"]},
                "verdict": "false_positive",
                "vex": {"products": ["pkg:npm/foo"], "justification": "seemed_fine"},
            }
        )


def test_expired_suppression_is_excluded():
    document, warnings = vex_mod.export(
        REPO_ROOT / "registry",
        author="test@example.org",
        doc_id="urn:vex:test:2",
        timestamp="2028-01-01T00:00:00Z",
        today=dt.date(2028, 1, 1),  # past both seed review_by dates
    )
    assert document["statements"] == []
    assert any("EXCLUDED" in w for w in warnings)
