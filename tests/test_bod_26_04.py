"""Tests for the BOD 26-04 remediation-timeline engine.

Table 1 rows are transcribed verbatim from CISA BOD 26-04 (2026-06-10):
https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
"""
import pytest

import itertools

from vuln_evidence_registry.bod_26_04 import (
    assess,
    derive_points_from_cvss,
    kev_clock_tier,
    remediation_timeline,
)

# (exposed, kev, automatable, total_impact) → (days, forensic_triage)
TABLE_1_ROWS = [
    # row, exposed, kev,   auto,  total, days, triage
    (1,  True,  True,  True,  True,  3,    True),
    (2,  True,  True,  True,  False, 3,    False),
    (3,  True,  True,  False, True,  3,    True),
    (4,  True,  True,  False, False, 14,   False),
    (5,  True,  False, True,  True,  3,    False),
    (6,  True,  False, True,  False, 14,   False),
    (7,  True,  False, False, True,  14,   False),
    (8,  True,  False, False, False, 60,   False),
    (9,  False, True,  True,  True,  3,    True),
    (10, False, True,  True,  False, 14,   False),
    (11, False, True,  False, True,  14,   False),
    (12, False, True,  False, False, 14,   False),
    (13, False, False, True,  True,  60,   False),
    (14, False, False, True,  False, 60,   False),
    (15, False, False, False, True,  None, False),  # fix on system upgrade
    (16, False, False, False, False, None, False),  # fix on system upgrade
]


@pytest.mark.parametrize("row,exposed,kev,auto,total,days,triage", TABLE_1_ROWS)
def test_table_1_rows(row, exposed, kev, auto, total, days, triage):
    assert remediation_timeline(
        in_kev=kev, automatable=auto, total_impact=total, publicly_exposed=exposed
    ) == (days, triage), f"Table 1 row {row} mismatch"


def test_forensic_triage_only_on_3day_kev_total():
    """Forensic triage applies exactly to the KEV + total-control 3-day rows (1, 3, 9)."""
    triage_rows = [r for r in TABLE_1_ROWS if r[6]]
    assert [r[0] for r in triage_rows] == [1, 3, 9]
    assert all(r[2] and r[4] and r[5] == 3 for r in triage_rows)  # kev, total, 3 days


# ── CVSS fallback derivation ──────────────────────────────────────────────────

def test_derive_points_network_low_no_ui_full_cia():
    auto, impact = derive_points_from_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert auto == "yes"
    assert impact == "total"


def test_derive_points_local_partial():
    auto, impact = derive_points_from_cvss("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N")
    assert auto == "no"
    assert impact == "partial"


def test_derive_points_no_vector():
    assert derive_points_from_cvss(None) == (None, None)
    assert derive_points_from_cvss("") == (None, None)


# ── assess() composition ──────────────────────────────────────────────────────

def test_assess_cisa_adp_source():
    out = assess(
        in_kev=True,
        ssvc_exploitation="active",
        ssvc_automatable="yes",
        ssvc_technical_impact="total",
        ssvc_decision="Act",
    )
    assert out["source"] == "cisa_adp"
    assert out["exposed"] == {"days": 3, "forensic_triage": True}    # row 1
    assert out["internal"] == {"days": 3, "forensic_triage": True}   # row 9
    assert out["decision"] == "Act"


def test_assess_derived_from_cvss():
    out = assess(
        in_kev=False,
        ssvc_exploitation=None,
        ssvc_automatable=None,
        ssvc_technical_impact=None,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    assert out["source"] == "derived"
    assert out["automatable"] == "yes"
    assert out["technical_impact"] == "total"
    assert out["exposed"] == {"days": 3, "forensic_triage": False}   # row 5
    assert out["internal"] == {"days": 60, "forensic_triage": False}  # row 13
    assert out["exploitation"] == "none"


def test_assess_unavailable_worst_case():
    out = assess(
        in_kev=False,
        ssvc_exploitation=None,
        ssvc_automatable=None,
        ssvc_technical_impact=None,
        cvss_vector=None,
    )
    assert out["source"] == "unavailable"
    # Worst-case assumed (automatable + total) so timelines never under-triage.
    assert out["automatable"] == "yes"
    assert out["technical_impact"] == "total"
    assert out["exposed"]["days"] == 3


def test_assess_partial_adp_falls_back_to_derived():
    """One ADP point missing → fill the gap from the vector; source becomes derived."""
    out = assess(
        in_kev=True,
        ssvc_exploitation="active",
        ssvc_automatable="yes",
        ssvc_technical_impact=None,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    )
    assert out["source"] == "derived"
    assert out["technical_impact"] == "partial"
    assert out["exposed"] == {"days": 3, "forensic_triage": False}   # row 2
    assert out["internal"] == {"days": 14, "forensic_triage": False}  # row 10


def test_assess_poc_exploitation_fallback():
    out = assess(
        in_kev=False,
        ssvc_exploitation=None,
        ssvc_automatable="no",
        ssvc_technical_impact="partial",
        has_public_poc=True,
    )
    assert out["exploitation"] == "poc"
    assert out["source"] == "cisa_adp"
    assert out["internal"]["days"] is None  # row 16: fix on system upgrade


# ── kev_clock_tier() ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("auto,total", list(itertools.product(["yes", "no"], ["partial", "total"])))
def test_kev_exposed_branch_is_always_3_or_14_days(auto, total):
    """An exposed KEV entry is never 60-day or fix-on-upgrade — only 3 or 14 days
    (Table 1 rows 1-4)."""
    out = assess(
        in_kev=True,
        ssvc_exploitation="active",
        ssvc_automatable=auto,
        ssvc_technical_impact=total,
    )
    assert out["exposed"]["days"] in (3, 14)


def test_kev_clock_tier_mapping():
    # row 1: KEV + automatable + total → 3 days + forensic triage
    assert kev_clock_tier(assess(
        in_kev=True, ssvc_exploitation="active",
        ssvc_automatable="yes", ssvc_technical_impact="total",
    )) == "forensic"
    # row 3: KEV + not-automatable + total → 3 days + forensic triage
    assert kev_clock_tier(assess(
        in_kev=True, ssvc_exploitation="active",
        ssvc_automatable="no", ssvc_technical_impact="total",
    )) == "forensic"
    # row 2: KEV + automatable + partial → 3 days, no triage
    assert kev_clock_tier(assess(
        in_kev=True, ssvc_exploitation="active",
        ssvc_automatable="yes", ssvc_technical_impact="partial",
    )) == "3d"
    # row 4: KEV + not-automatable + partial → 14 days
    assert kev_clock_tier(assess(
        in_kev=True, ssvc_exploitation="active",
        ssvc_automatable="no", ssvc_technical_impact="partial",
    )) == "14d"


def test_kev_clock_tier_covers_every_exposed_kev_combo():
    """Every SSVC combo for an exposed KEV entry maps to one of the three tiers."""
    tiers = {
        kev_clock_tier(assess(
            in_kev=True, ssvc_exploitation="active",
            ssvc_automatable=auto, ssvc_technical_impact=total,
        ))
        for auto, total in itertools.product(["yes", "no"], ["partial", "total"])
    }
    assert tiers <= {"forensic", "3d", "14d"}
    assert tiers == {"forensic", "3d", "14d"}
