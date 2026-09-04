"""COVERAGE.md must agree with the data it claims to report.

A published table that silently drifts from its source is worse than no table: it keeps its
authority while losing its truth. These tests re-derive every headline figure in COVERAGE.md
from the committed inputs and assert the document still says the same thing.

If one of these fails, the fix is to regenerate the document, never to edit the assertion.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

PKG = Path(__file__).resolve().parents[1]
EVAL = PKG / "evaluation"
DOC = EVAL / "COVERAGE.md"
SCAN = EVAL / "data" / "kev_cvelist_scan_2026-09-02.json"
RUN = PKG / "pipeline" / "runs" / "edge-2023plus"
INPUTS = PKG / "pipeline" / "data" / "inputs.json"

sys.path.insert(0, str(EVAL))


@pytest.fixture(scope="module")
def doc() -> str:
    return DOC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def scan() -> list[dict]:
    return json.loads(SCAN.read_text(encoding="utf-8"))


def test_headline_configurations_rate(doc, scan):
    """1.2% of KEV, 21 of 1,687 — the number the whole note rests on."""
    filled = sum(1 for x in scan if x["configurations_len"])
    assert filled == 21, f"scan now shows {filled} filled containers; regenerate COVERAGE.md"
    assert len(scan) == 1687
    assert "**1.2%**" in doc
    assert "21 of 1,687" in doc


def test_headline_is_independently_confirmed(doc):
    """The cross-validation claim must actually hold: two code paths, same answer, no
    per-CVE disagreement. This is the claim a reviewer would check first."""
    inputs = json.loads(INPUTS.read_text(encoding="utf-8"))
    scan = {x["cve"]: x for x in json.loads(SCAN.read_text(encoding="utf-8"))}
    a = sum(1 for v in inputs.values() if v.get("has_configurations"))
    b = sum(1 for x in scan.values() if x["configurations_len"])
    assert a == b == 21
    shared = set(inputs) & set(scan)
    disagree = [
        c for c in shared
        if bool(inputs[c].get("has_configurations")) != bool(scan[c]["configurations_len"])
    ]
    assert not disagree, f"the two counts now disagree on {disagree[:5]}"
    assert "disagree on **none**" in doc


def test_adp_writes_no_precondition_text(doc, scan):
    """CISA Vulnrichment enriches nearly every KEV record but not with this."""
    adp = sum(1 for x in scan if x.get("adp_conf_len"))
    assert adp == 3
    assert "**0.2%**" in doc


def test_palo_alto_is_the_only_cna_that_fills_it(doc, scan):
    """The per-CNA claim: one of 25 rateable CNAs uses the field."""
    by: dict[str, list[dict]] = {}
    for x in scan:
        by.setdefault(x["cna"], []).append(x)
        
    rateable = {k: v for k, v in by.items() if len(v) >= 10}
    assert len(rateable) == 25, f"{len(rateable)} rateable CNAs now; regenerate the table"
    rates = {
        k: sum(1 for x in v if x["configurations_len"]) / len(v)
        for k, v in rateable.items()
    }
    above = {k for k, r in rates.items() if r > 0.05}
    assert above == {"palo_alto"}, f"CNAs above 5% are now {above}"
    assert abs(rates["palo_alto"] - 0.714) < 0.005
    assert "**71.4%**" in doc
    # The two objection-killers.
    assert abs(rates["fortinet"]) < 1e-9
    fortinet = rateable["fortinet"]
    sol = sum(1 for x in fortinet if x["solutions_len"]) / len(fortinet)
    assert abs(sol - 0.690) < 0.005, "the Fortinet solutions/configurations contrast moved"
    cisco_desc = sorted(x["desc_len"] for x in rateable["cisco"])[len(rateable["cisco"]) // 2]
    assert cisco_desc == 739, "Cisco's median description length moved"
    # QNAP is the second objection-killer and is cited in prose, so pin it too.
    qnap = rateable["qnap"]
    qsol = sum(1 for x in qnap if x["solutions_len"]) / len(qnap)
    assert abs(qsol - 0.417) < 0.005 and not any(x["configurations_len"] for x in qnap)


def test_within_cna_deconfound(doc):
    """The load-bearing rows: same assigner, with and without the container."""
    inputs = json.loads(INPUTS.read_text(encoding="utf-8"))
    scan = {x["cve"]: x for x in json.loads(SCAN.read_text(encoding="utf-8"))}
    rows = []
    for p in sorted(RUN.glob("CVE-*.yaml")):
        cve = p.stem
        rec = yaml.safe_load(p.read_text(encoding="utf-8"))
        rows.append({
            "gates": len((rec.get("expected") or {}).get("preconditions") or []),
            "container": bool(inputs.get(cve, {}).get("has_configurations")),
            "cna": (scan.get(cve) or {}).get("cna"),
        })
    assert len(rows) == 170

    pa = [r for r in rows if r["cna"] == "palo_alto"]
    filled = [r for r in pa if r["container"]]
    unfilled = [r for r in pa if not r["container"]]
    assert len(filled) == 8 and len(unfilled) == 3
    assert abs(sum(r["gates"] for r in filled) / 8 - 2.875) < 0.01
    assert sum(r["gates"] for r in unfilled) == 0, "the 0.00 row is the whole argument"
    assert all(r["gates"] > 0 for r in filled)
    assert "**0.00**" in doc and "**3 / 3 (100%)**" in doc

    allf = [r for r in rows if r["container"]]
    alln = [r for r in rows if not r["container"]]
    assert len(allf) == 13 and len(alln) == 157
    assert sum(1 for r in allf if r["gates"] == 0) == 0
    assert sum(1 for r in alln if r["gates"] == 0) == 50


def test_every_percentage_in_the_doc_is_sourced(doc):
    """No stray figure: every bare percentage must appear in a table row or be one of the
    named, explained numbers. Cheap guard against a number arriving by hand later."""
    known = {
        "1.2", "2.7", "5.1", "0.2", "71.4", "92.9", "0.3", "0.9", "0.0", "69.0", "42",
        "32", "0", "100", "45", "88", "89", "93",
        "69",  # prose writes "69%" where the table writes "69.0%" — same number
    }
    # Strip confidence-LEVEL labels first ("Wilson 95%", "95% CI"). They are not data, and
    # whitelisting "95" instead would let a genuine stray 95% through unnoticed — which is
    # exactly the drift this test exists to catch.
    body = re.sub(r"(?:Wilson\s+)?95%(?:\s+CI)?", "", doc)
    # And interval BOUNDS — "[1%, 2%]" is computed by wilson() from the same counts the
    # point estimate comes from, so it is generated data, not a figure anyone typed. The
    # point estimates it brackets are asserted individually above.
    body = re.sub(r"\[\s*\d+(?:\.\d+)?%\s*,\s*\d+(?:\.\d+)?%\s*\]", "", body)
    for m in re.finditer(r"(\d+(?:\.\d+)?)%", body):
        assert m.group(1) in known, f"unsourced percentage {m.group(0)} in COVERAGE.md"
