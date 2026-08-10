"""Suppression stage: verified verdicts that beat everything, matched exactly.

The two properties worth guarding hardest:
  1. cve_id/qid match by EXACT equality — the default contained-in semantics
     would let CVE-2021-4428 suppress CVE-2021-44228 findings.
  2. A suppression cannot exist without verdict, provenance, evidence, and
     review_by — silencing detections is a lease with a paper trail.
"""

from pathlib import Path

import pytest

from routing_registry import (
    RegistryError,
    load_registry,
    propose_suppression,
    route_finding,
    stats,
    route_all,
)
from routing_registry.router import _match_subject

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def registry():
    return load_registry(ROOT / "registry")


# --- exact identifier matching -------------------------------------------

def test_cve_id_substring_does_not_match():
    assert not _match_subject(
        {"cve_id": ["CVE-2021-4428"]}, {"cve_id": "CVE-2021-44228"}
    )


def test_cve_id_exact_matches_case_insensitively():
    assert _match_subject({"cve_id": ["cve-2021-44228"]}, {"cve_id": "CVE-2021-44228"})


def test_qid_substring_does_not_match():
    assert not _match_subject({"qid": ["37615"]}, {"qid": "376157"})


def test_vendor_keeps_contained_semantics():
    assert _match_subject({"vendor": ["red hat"]}, {"vendor": "Red Hat, Inc."})


# --- routing behaviour ----------------------------------------------------

def test_suppression_beats_screens_and_routing(registry):
    # A rejected-status finding with a suppressed QID: suppression wins even
    # though screen-rejected would also match.
    result = route_finding(
        {
            "id": "f-1",
            "cve_id": "CVE-2021-44228",
            "qid": "376157",
            "nvd_status": "Rejected",
            "product": "Log4j 1.2.17",
        },
        registry,
    )
    assert result.disposition == "suppressed"
    assert result.stage == "suppression"
    assert result.rule_id == "sup-20260809-log4j1-version-match"
    assert result.verdict == "false_positive"


def test_conditional_suppression_needs_context_present(registry):
    finding = {
        "id": "f-2",
        "cve_id": "CVE-2022-22965",
        "purl": "pkg:maven/org.springframework/spring-beans@5.3.17",
        "description": "Spring4Shell",
    }
    assert route_finding(finding, registry).disposition == "routed"
    finding["context"] = {"config_vulnerable": False}
    suppressed = route_finding(finding, registry)
    assert suppressed.disposition == "suppressed"
    assert suppressed.verdict == "not_applicable_config"


def test_expired_suppression_stops_silencing_and_resurfaces(registry):
    import datetime as dt

    finding = {"id": "f-lg", "cve_id": "CVE-2021-44228", "qid": "376157",
               "product": "Log4j 1.2.17"}
    # Active today: suppressed.
    assert route_finding(finding, registry, today=dt.date(2026, 8, 9)).disposition == "suppressed"
    # After the seed rule's review_by (2027-08-01): the lapsed lease must not
    # keep hiding the finding — it falls through and resurfaces for triage.
    lapsed = route_finding(finding, registry, today=dt.date(2028, 1, 1))
    assert lapsed.disposition != "suppressed"


def test_stats_counts_suppressed(registry):
    results = route_all(
        [
            {"id": "a", "cve_id": "CVE-2021-44228", "qid": "376157"},
            {"id": "b", "vendor": "Oracle", "product": "WebLogic Server"},
        ],
        registry,
    )
    s = stats(results)
    assert s["suppressed"] == 1
    assert s["routed"] == 1


# --- loader discipline ----------------------------------------------------

def _write_minimal_registry(root: Path, suppression_yaml: str):
    (root / "rules").mkdir(parents=True)
    (root / "channels.yaml").write_text(
        "- id: ch-a\n  name: A\n  cadence_type: ad_hoc\n", encoding="utf-8"
    )
    (root / "screens.yaml").write_text("[]", encoding="utf-8")
    (root / "rules" / "identity.yaml").write_text(
        "- id: id-a\n  match: {vendor: [acme]}\n  route: ch-a\n", encoding="utf-8"
    )
    (root / "rules" / "corrections.yaml").write_text("[]", encoding="utf-8")
    (root / "rules" / "suppressions.yaml").write_text(suppression_yaml, encoding="utf-8")


_PROV = "{date: '2026-01-01', decided_by: a, trigger: t, evidence: e}"


@pytest.mark.parametrize(
    "missing, yaml_text",
    [
        (
            "verdict",
            f"- id: sup-x\n  match: {{qid: ['1']}}\n"
            f"  provenance: {_PROV}\n  review_by: '2027-01-01'\n",
        ),
        (
            "review_by",
            f"- id: sup-x\n  match: {{qid: ['1']}}\n  verdict: false_positive\n"
            f"  provenance: {_PROV}\n",
        ),
        (
            "provenance",
            "- id: sup-x\n  match: {qid: ['1']}\n  verdict: false_positive\n"
            "  review_by: '2027-01-01'\n",
        ),
        (
            "evidence",
            "- id: sup-x\n  match: {qid: ['1']}\n  verdict: false_positive\n"
            "  provenance: {date: '2026-01-01', decided_by: a, trigger: t}\n"
            "  review_by: '2027-01-01'\n",
        ),
        (
            "match",
            f"- id: sup-x\n  verdict: false_positive\n"
            f"  provenance: {_PROV}\n  review_by: '2027-01-01'\n",
        ),
    ],
)
def test_loader_rejects_incomplete_suppression(tmp_path, missing, yaml_text):
    _write_minimal_registry(tmp_path, yaml_text)
    with pytest.raises(RegistryError):
        load_registry(tmp_path)


# --- propose_suppression workflow ----------------------------------------

def test_propose_suppression_appends_and_fixture(tmp_path):
    _write_minimal_registry(tmp_path, "[]")
    fixtures = tmp_path / "fixtures.yaml"
    rule_id = propose_suppression(
        tmp_path,
        match={"qid": ["12345"]},
        verdict="false_positive",
        decided_by="tester",
        trigger="QID matches wrong product",
        evidence="verified against SBOM",
        review_by="2027-01-01",
        fixture_finding={"id": "f-x", "qid": "12345"},
        fixtures_path=fixtures,
    )
    registry = load_registry(tmp_path)
    assert route_finding({"id": "f-x", "qid": "12345"}, registry).rule_id == rule_id
    assert rule_id in fixtures.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "kwargs, message",
    [
        (dict(match={}), "match predicate"),
        (dict(verdict="nope"), "verdict must be one of"),
        (dict(evidence=""), "evidence is mandatory"),
        (dict(review_by=""), "review_by is mandatory"),
    ],
)
def test_propose_suppression_enforces_discipline(tmp_path, kwargs, message):
    _write_minimal_registry(tmp_path, "[]")
    base = dict(
        match={"qid": ["12345"]},
        verdict="false_positive",
        decided_by="tester",
        trigger="t",
        evidence="e",
        review_by="2027-01-01",
    )
    base.update(kwargs)
    with pytest.raises(ValueError, match=message):
        propose_suppression(tmp_path, **base)
