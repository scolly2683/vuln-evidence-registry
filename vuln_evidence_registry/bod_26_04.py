"""BOD 26-04 remediation-timeline engine (CISA, issued 2026-06-10).

Encodes Table 1: Remediation Timelines from CISA Binding Operational Directive
26-04 "Prioritizing Security Updates Based on Risk", which supersedes BOD 22-01
(KEV due dates) and BOD 19-02. The timeline for a vulnerability instance is a
function of four variables:

  - Publicly Exposed (asset-level — org-specific, so we compute BOTH branches)
  - In the KEV
  - Automatable by Adversary  (an SSVC decision point)
  - Technical Impact          (an SSVC decision point)

This is a categorical/regulatory lens — "what does the federal clock say" — and
is deliberately independent of any empirical risk score.

Reference: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
"""
from __future__ import annotations

import re

# Timeline sentinel: None days = "fix on system upgrade" (Table 1 rows 15-16).
FIX_ON_UPGRADE: int | None = None

# Table 1, keyed (publicly_exposed, in_kev, automatable, total_impact) →
# (days, forensic_triage). Transcribed verbatim from the directive's table.
_TABLE_1: dict[tuple[bool, bool, bool, bool], tuple[int | None, bool]] = {
    (True,  True,  True,  True):  (3, True),    # row 1
    (True,  True,  True,  False): (3, False),   # row 2
    (True,  True,  False, True):  (3, True),    # row 3
    (True,  True,  False, False): (14, False),  # row 4
    (True,  False, True,  True):  (3, False),   # row 5
    (True,  False, True,  False): (14, False),  # row 6
    (True,  False, False, True):  (14, False),  # row 7
    (True,  False, False, False): (60, False),  # row 8
    (False, True,  True,  True):  (3, True),    # row 9
    (False, True,  True,  False): (14, False),  # row 10
    (False, True,  False, True):  (14, False),  # row 11
    (False, True,  False, False): (14, False),  # row 12
    (False, False, True,  True):  (60, False),  # row 13
    (False, False, True,  False): (60, False),  # row 14
    (False, False, False, True):  (FIX_ON_UPGRADE, False),  # row 15
    (False, False, False, False): (FIX_ON_UPGRADE, False),  # row 16
}


def remediation_timeline(
    in_kev: bool,
    automatable: bool,
    total_impact: bool,
    publicly_exposed: bool,
) -> tuple[int | None, bool]:
    """Table 1 lookup → (days, forensic_triage). days=None → fix on system upgrade."""
    return _TABLE_1[(publicly_exposed, in_kev, automatable, total_impact)]


def kev_clock_tier(assessment: dict) -> str:
    """Map a BOD 26-04 assessment's EXPOSED branch to a KEV remediation tier.

    A KEV entry on a publicly exposed asset always lands at 3 or 14 days (Table 1
    rows 1-4 — never 60-day or fix-on-upgrade), so the KEV clock has exactly three
    tiers: 'forensic' (3 days + forensic triage), '3d' (3 days, no triage), '14d'.
    """
    exposed = assessment["exposed"]
    if exposed["days"] == 3 and exposed["forensic_triage"]:
        return "forensic"
    if exposed["days"] == 3:
        return "3d"
    return "14d"


# ── CVSS-vector fallback derivation ──────────────────────────────────────────
# Used when authoritative SSVC decision points have not been published for a CVE.

def _vector_field(vector: str, key: str) -> str | None:
    # Anchor on start-of-string or '/' — a bare "C:" pattern would match inside
    # "AC:L" and silently read attack complexity as confidentiality.
    m = re.search(rf"(?:^|/){key}:([^/]+)", vector)
    return m.group(1) if m else None


def derive_points_from_cvss(vector: str | None) -> tuple[str | None, str | None]:
    """Derive (automatable, technical_impact) from a CVSS v3 vector.

    automatable yes ⇐ AV:N + AC:L + UI:N; technical_impact total ⇐ C:H+I:H+A:H.
    Returns (None, None) when no vector is available.
    """
    if not vector:
        return None, None
    av = _vector_field(vector, "AV")
    ac = _vector_field(vector, "AC")
    ui = _vector_field(vector, "UI")
    c = _vector_field(vector, "C")
    i = _vector_field(vector, "I")
    a = _vector_field(vector, "A")
    automatable = "yes" if (av == "N" and ac == "L" and ui == "N") else "no"
    total = "total" if (c == "H" and i == "H" and a == "H") else "partial"
    return automatable, total


def assess(
    *,
    in_kev: bool,
    ssvc_exploitation: str | None,
    ssvc_automatable: str | None,
    ssvc_technical_impact: str | None,
    ssvc_decision: str | None = None,
    cvss_vector: str | None = None,
    has_public_poc: bool = False,
) -> dict:
    """Compose the BOD 26-04 assessment for one CVE — both exposure branches.

    Provenance: 'cisa_adp' when authoritative SSVC points are supplied;
    'derived' when falling back to the CVSS-vector heuristic; 'unavailable'
    when neither exists (timelines are then computed worst-case so a consumer
    never under-triages, and the source flag lets the UI say so).
    """
    automatable = ssvc_automatable
    technical_impact = ssvc_technical_impact

    if automatable in ("yes", "no") and technical_impact in ("partial", "total"):
        source = "cisa_adp"
    else:
        d_auto, d_impact = derive_points_from_cvss(cvss_vector)
        automatable = automatable if automatable in ("yes", "no") else d_auto
        technical_impact = (
            technical_impact if technical_impact in ("partial", "total") else d_impact
        )
        if automatable and technical_impact:
            source = "derived"
        else:
            # Worst-case assumption — never under-triage.
            source = "unavailable"
            automatable = automatable or "yes"
            technical_impact = technical_impact or "total"

    exploitation = ssvc_exploitation or (
        "active" if in_kev else "poc" if has_public_poc else "none"
    )

    exposed_days, exposed_triage = remediation_timeline(
        in_kev, automatable == "yes", technical_impact == "total", publicly_exposed=True
    )
    internal_days, internal_triage = remediation_timeline(
        in_kev, automatable == "yes", technical_impact == "total", publicly_exposed=False
    )

    return {
        "source": source,
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical_impact,
        "decision": ssvc_decision,
        "exposed": {"days": exposed_days, "forensic_triage": exposed_triage},
        "internal": {"days": internal_days, "forensic_triage": internal_triage},
    }
