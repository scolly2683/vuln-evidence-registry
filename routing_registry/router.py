"""Deterministic routing engine.

Pipeline per finding:
  0. suppressions — verified false positives and not-applicable-by-config
                    verdicts; they beat everything, because a detection that
                    is wrong must not consume any downstream decision
  1. screens      — drop or park before channel routing (rejected records,
                    out-of-program classes, bulk-feed noise)
  2. corrections  — learned context-aware rules; most specific, fire first
  3. identity     — "what software is this" rules seeded from cohort analysis
  4. unroutable   — the adjudication queue; every entry here should end its
                    life as a new rule

First full match wins. Within a stage, rules fire in (priority, id) order.
No ML anywhere: the learning is in the accumulated correction data.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from .models import EXACT_SUBJECT_FIELDS, Registry, RouteResult


def _norm(value: object) -> str:
    return str(value).strip().lower() if value is not None else ""


def _match_subject(match: dict, finding: dict) -> bool:
    """All predicates must hold. Empty match block matches everything
    (useful only for screens with a context predicate — identity rules are
    validated to route somewhere so an empty match there is a design smell).
    """
    for key, expected in match.items():
        if key == "purl_prefix":
            purl = _norm(finding.get("purl"))
            prefixes = expected if isinstance(expected, list) else [expected]
            if not purl or not any(purl.startswith(_norm(p)) for p in prefixes):
                return False
        elif key == "keywords":
            # Case-insensitive substring over product + package + description.
            hay = " ".join(
                _norm(finding.get(f)) for f in ("product", "package", "description")
            )
            words = expected if isinstance(expected, list) else [expected]
            if not any(_norm(w) in hay for w in words):
                return False
        elif key in EXACT_SUBJECT_FIELDS:
            # Identifiers match by EXACT equality only — contained-in would
            # let CVE-2021-4428 match CVE-2021-44228.
            value = _norm(finding.get(key))
            allowed = expected if isinstance(expected, list) else [expected]
            if not value or not any(_norm(a) == value for a in allowed):
                return False
        else:
            value = _norm(finding.get(key))
            allowed = expected if isinstance(expected, list) else [expected]
            # Equal or contained: "red hat" matches "Red Hat, Inc.".
            if not value or not any(_norm(a) == value or _norm(a) in value for a in allowed):
                return False
    return True


def _match_context(pred: dict, context: dict) -> bool:
    """A context predicate only fires when the key is PRESENT and matches.

    Absent context never satisfies a predicate — a correction must not fire
    on findings whose deployment context is unknown. That keeps corrections
    safe by default: no data, no override.
    """
    for key, expected in pred.items():
        if key not in context:
            return False
        actual = context[key]
        if isinstance(expected, dict):
            if "in" in expected and actual not in expected["in"]:
                return False
            if "not" in expected and actual == expected["not"]:
                return False
        elif actual != expected:
            return False
    return True


def route_finding(finding: dict, registry: Registry) -> RouteResult:
    fid = str(finding.get("id") or finding.get("finding_id") or "")
    cve = str(finding.get("cve_id") or "")
    context = finding.get("context") or {}

    for rule in registry.rules_of_kind("suppression"):
        if _match_subject(rule.match, finding) and _match_context(rule.context, context):
            return RouteResult(
                finding_id=fid,
                cve_id=cve,
                disposition="suppressed",
                rule_id=rule.id,
                stage="suppression",
                verdict=rule.verdict,
            )

    for rule in registry.rules_of_kind("screen"):
        if _match_subject(rule.match, finding) and _match_context(rule.context, context):
            return RouteResult(
                finding_id=fid,
                cve_id=cve,
                disposition="screened",
                rule_id=rule.id,
                stage="screen",
                queue=rule.queue if rule.action == "park" else None,
            )

    for kind in ("correction", "identity"):
        for rule in registry.rules_of_kind(kind):
            if _match_subject(rule.match, finding) and _match_context(rule.context, context):
                return RouteResult(
                    finding_id=fid,
                    cve_id=cve,
                    disposition="routed",
                    channel=rule.route,
                    rule_id=rule.id,
                    stage=kind,
                )

    return RouteResult(finding_id=fid, cve_id=cve, disposition="unroutable")


def route_all(findings: Iterable[dict], registry: Registry) -> list[RouteResult]:
    return [route_finding(f, registry) for f in findings]


def stats(results: list[RouteResult]) -> dict:
    """The convergence metric lives here: unroutable_pct, run over run."""
    total = len(results)
    dispositions = Counter(r.disposition for r in results)
    channels = Counter(r.channel for r in results if r.channel)
    stages = Counter(r.stage for r in results if r.stage)
    unroutable = dispositions.get("unroutable", 0)
    return {
        "total": total,
        "suppressed": dispositions.get("suppressed", 0),
        "screened": dispositions.get("screened", 0),
        "routed": dispositions.get("routed", 0),
        "unroutable": unroutable,
        "unroutable_pct": round(100.0 * unroutable / total, 1) if total else 0.0,
        "by_channel": dict(channels.most_common()),
        "by_stage": dict(stages),
    }
