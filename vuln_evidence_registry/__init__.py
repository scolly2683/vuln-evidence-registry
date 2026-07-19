"""vuln-evidence-registry — two reusable vulnerability-prioritisation patterns.

* ``evidence_sources`` — a declarative registry that is the single source of
  truth for both a SQL gate and its pure-Python predicate twin, so the two can
  never drift.
* ``bod_26_04`` — the CISA BOD 26-04 remediation-timeline engine (Table 1 as
  code).
"""
from __future__ import annotations

from .bod_26_04 import (
    assess,
    derive_points_from_cvss,
    kev_clock_tier,
    remediation_timeline,
)
from .evidence_sources import (
    ACT_NOW_EPSS_THRESHOLD,
    EPSS_THRESHOLD,
    REGISTRY,
    EvidenceContext,
    EvidenceSource,
    act_now_union_sql,
    evaluate_gate,
    gate_union_sql,
)

__all__ = [
    "REGISTRY",
    "EvidenceContext",
    "EvidenceSource",
    "EPSS_THRESHOLD",
    "ACT_NOW_EPSS_THRESHOLD",
    "gate_union_sql",
    "act_now_union_sql",
    "evaluate_gate",
    "assess",
    "remediation_timeline",
    "kev_clock_tier",
    "derive_points_from_cvss",
]
