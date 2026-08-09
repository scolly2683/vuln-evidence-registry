"""Append-on-misroute: turn a routing correction into registry data.

A correction is appended (never rewritten) to rules/corrections.yaml, and the
triggering finding is appended to fixtures/regression.yaml so the next run —
and CI forever after — must route it correctly. Git is the review and audit
layer: a correction lands as a diff someone approves, and `git blame` is the
provenance trail.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import yaml

from .loader import RegistryError, load_registry
from .models import SUPPRESSION_VERDICTS


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40]


def _append_yaml_entry(path: Path, entry: dict, header_comment: str | None = None) -> None:
    """Append one entry to a top-level-list YAML file without rewriting it,
    so existing comments and history stay byte-for-byte intact."""
    block = yaml.safe_dump([entry], sort_keys=False, allow_unicode=True, width=100)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_text(encoding="utf-8").strip() in ("", "[]"):
        text = (header_comment or "") + block
        path.write_text(text, encoding="utf-8")
        return
    with path.open("a", encoding="utf-8") as fh:
        if header_comment:
            fh.write(header_comment)
        fh.write(block)


def propose_correction(
    registry_dir: str | Path,
    *,
    route: str,
    match: dict,
    context: dict,
    decided_by: str,
    trigger: str,
    evidence: str = "",
    review_by: str | None = None,
    note: str = "",
    fixture_finding: dict | None = None,
    fixtures_path: str | Path | None = None,
    today: dt.date | None = None,
) -> str:
    """Append a correction rule (and optionally a regression fixture).

    Returns the generated rule id. Validates the amended registry before
    returning — an appended correction that breaks the registry is rolled
    back rather than left in place.
    """
    if not match:
        raise ValueError("a correction needs at least one subject match predicate")
    if not context:
        raise ValueError(
            "a correction needs a context predicate — if the route is wrong for "
            "EVERY instance of this subject, fix the identity rule instead"
        )
    root = Path(registry_dir)
    today = today or dt.date.today()
    basis = "-".join(str(v) for v in list(match.values())[:1] + list(context.keys())[:1])
    rule_id = f"corr-{today.strftime('%Y%m%d')}-{_slug(basis) or 'unnamed'}"

    corrections_path = root / "rules" / "corrections.yaml"
    original = corrections_path.read_text(encoding="utf-8") if corrections_path.exists() else None

    entry: dict = {
        "id": rule_id,
        "match": match,
        "context": context,
        "route": route,
        "provenance": {
            "date": today.isoformat(),
            "decided_by": decided_by,
            "trigger": trigger,
        },
    }
    if evidence:
        entry["provenance"]["evidence"] = evidence
    if review_by:
        entry["review_by"] = review_by
    if note:
        entry["note"] = note

    _append_yaml_entry(corrections_path, entry, header_comment=f"\n# {today.isoformat()}\n")

    try:
        load_registry(root, today=today)
    except RegistryError:
        # Roll back the append so a bad correction can't poison the registry.
        if original is None:
            corrections_path.unlink(missing_ok=True)
        else:
            corrections_path.write_text(original, encoding="utf-8")
        raise

    if fixture_finding is not None:
        fixtures = Path(fixtures_path) if fixtures_path else root.parent / "fixtures" / "regression.yaml"
        _append_yaml_entry(
            fixtures,
            {
                "name": rule_id,
                "finding": fixture_finding,
                "expect": {"disposition": "routed", "channel": route, "rule_id": rule_id},
            },
        )
    return rule_id


def propose_suppression(
    registry_dir: str | Path,
    *,
    match: dict,
    verdict: str,
    decided_by: str,
    trigger: str,
    evidence: str,
    review_by: str,
    context: dict | None = None,
    note: str = "",
    fixture_finding: dict | None = None,
    fixtures_path: str | Path | None = None,
    today: dt.date | None = None,
) -> str:
    """Append a suppression verdict (and optionally a regression fixture).

    Same discipline as corrections — append-only, validated, rolled back on
    error — with two stricter requirements: `evidence` and `review_by` are
    mandatory. A suppression silences detections; one without evidence is an
    unmanaged risk acceptance, and one without an expiry is permanent.
    Unlike corrections, `context` is optional: a false-positive QID needs no
    deployment condition, while a not-applicable-by-config verdict should
    carry one (e.g. ``config_vulnerable=false``).
    """
    if not match:
        raise ValueError("a suppression needs at least one match predicate (cve_id, qid, ...)")
    if verdict not in SUPPRESSION_VERDICTS:
        raise ValueError(f"verdict must be one of {SUPPRESSION_VERDICTS}, got {verdict!r}")
    if not evidence:
        raise ValueError("evidence is mandatory — a suppression without evidence is an unmanaged risk acceptance")
    if not review_by:
        raise ValueError("review_by is mandatory — a suppression is a lease, not a tombstone")

    root = Path(registry_dir)
    today = today or dt.date.today()
    basis = "-".join(str(v) for v in list(match.values())[:1])
    rule_id = f"sup-{today.strftime('%Y%m%d')}-{_slug(basis) or 'unnamed'}"

    suppressions_path = root / "rules" / "suppressions.yaml"
    original = suppressions_path.read_text(encoding="utf-8") if suppressions_path.exists() else None

    entry: dict = {
        "id": rule_id,
        "match": match,
    }
    if context:
        entry["context"] = context
    entry["verdict"] = verdict
    entry["provenance"] = {
        "date": today.isoformat(),
        "decided_by": decided_by,
        "trigger": trigger,
        "evidence": evidence,
    }
    entry["review_by"] = review_by
    if note:
        entry["note"] = note

    _append_yaml_entry(suppressions_path, entry, header_comment=f"\n# {today.isoformat()}\n")

    try:
        load_registry(root, today=today)
    except RegistryError:
        if original is None:
            suppressions_path.unlink(missing_ok=True)
        else:
            suppressions_path.write_text(original, encoding="utf-8")
        raise

    if fixture_finding is not None:
        fixtures = Path(fixtures_path) if fixtures_path else root.parent / "fixtures" / "regression.yaml"
        _append_yaml_entry(
            fixtures,
            {
                "name": rule_id,
                "finding": fixture_finding,
                "expect": {"disposition": "suppressed", "rule_id": rule_id},
            },
        )
    return rule_id
