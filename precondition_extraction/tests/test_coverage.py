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
        "71",  # prose writes "71%" where the table writes "71.4%"
        "9.1",  # CNAScoreCard's share of CNAs (NOT records) — see test_prior_art_is_quoted_exactly
        "0.34", "78",  # Konvu's published figures — see test_konvu_prior_art_is_quoted_exactly
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


def test_kev_rate_by_year(doc):
    """The temporal table: the 1.2% is weighted by a pre-2020 tail where the field did not
    exist in practice. Saying so is what stops it being compared naively with other windows."""
    scan = json.loads(SCAN.read_text(encoding="utf-8"))
    buckets = {"pre-2020": [0, 0], "2020-2023": [0, 0], "2024+": [0, 0]}
    for x in scan:
        y = int(x["cve"].split("-")[1])
        b = "pre-2020" if y < 2020 else ("2020-2023" if y <= 2023 else "2024+")
        buckets[b][0] += 1
        buckets[b][1] += 1 if x["configurations_len"] else 0
    assert buckets["pre-2020"] == [555, 0], buckets
    assert buckets["2020-2023"] == [658, 8], buckets
    assert buckets["2024+"] == [474, 13], buckets
    for row in ("| pre-2020 | 555 | 0 |", "| 2020–2023 | 658 | 8 |", "| 2024+ | 474 | 13 |"):
        assert row in doc, f"missing temporal row: {row}"


def test_prior_art_is_quoted_exactly(doc):
    """CNAScoreCard's figure is prior art and is QUOTED, not re-derived — this repo holds no
    all-CVE population. The guard is therefore self-consistency: the percentage in the prose
    must match the JSON blob the note reproduces, so the two can never drift apart silently.
    If CNAScoreCard republishes a different number, update both together."""
    blob = re.search(r'\{"field": "containers\.cna\.configurations".*?\}', doc, re.S)
    assert blob, "the quoted CNAScoreCard record is missing"
    quoted = json.loads(re.sub(r"\s+", " ", blob.group(0)))
    assert quoted["percent"] == 9.1 and quoted["unique_cnas"] == 31
    assert quoted["cna_scorecard_category"] is None, (
        "the note's whole ask is that this field is tracked but UNSCORED (null category)"
    )
    assert "share of *assigners*" in doc, (
        "the note must state that 9.1% is a share of CNAs, not of records — an earlier draft "
        "compared it directly with a record-level rate, which was wrong"
    )
    assert "That was wrong." in doc, "the correction must remain visible, not be quietly dropped"
    assert "Jerry Gamblin" in doc and "CNAScoreCard" in doc, "prior art must be credited"


def test_konvu_prior_art_is_quoted_exactly(doc):
    """Konvu's comment is the live campaign and the record-level number. Their figures are
    QUOTED from https://konvu.com/blog/how-to-fix-the-nvd (18 Aug 2026), not re-derived —
    this repo holds no all-CVE population — so the guard is internal consistency: the counts
    and the percentage must agree with each other and with the prose."""
    m = re.search(r"populated in \*\*([\d,]+) of ([\d,]+) published records\*\*", doc)
    assert m, "the Konvu record count must be quoted verbatim"
    filled, total = (int(x.replace(",", "")) for x in m.groups())
    assert filled == 1211 and total == 360436
    assert abs(100 * filled / total - 0.34) < 0.005, "0.34% must match the quoted counts"
    assert "Six organizations write 78 percent" in doc
    assert "konvu.com/blog/how-to-fix-the-nvd" in doc, "prior art must be linked"
    assert "Make `configurations` structured, and require it where the CNA already knows" in doc


def test_the_open_rfi_deadline_is_stated(doc):
    """Route 0 is the only ask with a clock on it. If this note outlives the deadline the
    text must be revised, so the date is asserted rather than left to rot silently."""
    assert "NIST-2026-0100" in doc
    assert "13 October 2026" in doc
    assert "regulations.gov" in doc
    assert "2026-16371" in doc, "cite the Federal Register document number"
