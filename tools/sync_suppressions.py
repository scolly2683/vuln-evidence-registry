#!/usr/bin/env python3
"""Plan and reconcile scanner-side suppressions against the registry.

The registry (rules/suppressions.yaml) is the source of truth for what is
suppressed and why. Scanners are sinks: Qualys carries QID exclusions
(search lists), Wiz carries CVE ignore rules. This tool keeps the sinks
honest in both directions:

    plan       — desired scanner state, computed from ACTIVE suppressions
                 (expired ones drop out automatically)
    reconcile  — diff a console export against the desired state:
                   MISSING    in the registry, not in the tool  -> add
                   EXPIRED    in the tool, registry rule expired -> remove
                   UNMANAGED  in the tool, no registry rule      -> the exact
                              thing this design exists to eliminate: an
                              unaudited, unexpiring risk acceptance

Both commands are OFFLINE — they read files, not APIs — so they work
before any API onboarding. Feed `reconcile` an export from the console:

    python tools/sync_suppressions.py plan --registry registry
    python tools/sync_suppressions.py reconcile --registry registry \
        --tool qualys --actual qualys-exclusions.txt
    python tools/sync_suppressions.py reconcile --registry registry \
        --tool wiz --actual wiz-ignore-rules.json

Accepted --actual formats (deliberately forgiving):
    qualys — any text/CSV; QIDs are extracted as standalone numbers
    wiz    — JSON: a list of CVE strings, or a list of objects with a
             cve / cve_id / cves / name field

Exit codes: 0 clean, 1 reconcile found drift, 2 error. Wire `reconcile`
into CI or a weekly job and treat exit 1 as a page-worthy signal.

Live-apply (a later step, once API onboarding exists): Qualys — create or
update a static search list of the planned QIDs and reference it from an
exclusion option profile (Qualys API: /api/2.0/fo/qid/search_list/static/).
Wiz — manage ignore rules via the GraphQL API (securityFrameworks /
ignoreRules mutations). Keep both scoped to objects tagged as
registry-managed so reconcile can tell ours from everyone else's.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from routing_registry.loader import RegistryError, load_registry  # noqa: E402


def _load_suppressions(registry_dir: Path) -> list[dict]:
    load_registry(registry_dir)  # structural validation first
    path = registry_dir / "rules" / "suppressions.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) or [] if path.exists() else []


def _is_expired(entry: dict, today: dt.date) -> bool:
    review_by = entry.get("review_by")
    return bool(review_by) and dt.date.fromisoformat(str(review_by)) < today


def _values(match: dict, key: str) -> list[str]:
    value = match.get(key)
    if value is None:
        return []
    return [str(v) for v in (value if isinstance(value, list) else [value])]


def desired_state(registry_dir: Path, today: dt.date | None = None) -> dict:
    """Desired scanner state from ACTIVE suppressions.

    Returns {"qualys": {qid: rule_id}, "wiz": {cve: rule_id},
             "expired": {"qualys": {qid: rule_id}, "wiz": {cve: rule_id}}}.
    The expired sets are what reconcile uses to say "remove" rather than
    "unmanaged" for detections whose registry rule has lapsed.
    """
    today = today or dt.date.today()
    state: dict = {"qualys": {}, "wiz": {}, "expired": {"qualys": {}, "wiz": {}}}
    for entry in _load_suppressions(registry_dir):
        rule_id = entry.get("id", "?")
        match = entry.get("match") or {}
        bucket = state["expired"] if _is_expired(entry, today) else state
        for qid in _values(match, "qid"):
            bucket["qualys"][qid] = rule_id
        # Wiz ignore rules are CVE-keyed: use the vex block's CVE when the
        # match is QID-only, else the match CVEs.
        cves = _values(match, "cve_id") or _values(entry.get("vex") or {}, "cve")
        for cve in cves:
            bucket["wiz"][cve.upper()] = rule_id
    return state


def parse_actual(tool: str, path: Path) -> set[str]:
    """Identifiers currently suppressed in the tool, from a console export."""
    text = path.read_text(encoding="utf-8")
    if tool == "qualys":
        # Any standalone 5-7 digit number is treated as a QID.
        return set(re.findall(r"\b(\d{5,7})\b", text))
    data = json.loads(text)
    cves: set[str] = set()
    for item in data:
        if isinstance(item, str):
            cves.add(item.upper())
            continue
        for key in ("cve", "cve_id", "name"):
            if item.get(key):
                cves.add(str(item[key]).upper())
                break
        for value in item.get("cves", []):
            cves.add(str(value).upper())
    return {c for c in cves if c.startswith("CVE-")}


def reconcile(tool: str, actual: set[str], state: dict) -> dict:
    desired = state[tool]
    expired = state["expired"][tool]
    return {
        "missing": sorted(set(desired) - actual),        # add to the tool
        "expired": sorted(actual & set(expired)),        # remove from the tool
        "unmanaged": sorted(actual - set(desired) - set(expired)),
        "managed": sorted(actual & set(desired)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan", help="print desired scanner state from the registry")
    p_plan.add_argument("--registry", default=Path("registry"), type=Path)
    p_plan.add_argument("--out", type=Path, default=None, help="also write plan JSON here")

    p_rec = sub.add_parser("reconcile", help="diff a console export against the registry")
    p_rec.add_argument("--registry", default=Path("registry"), type=Path)
    p_rec.add_argument("--tool", required=True, choices=["qualys", "wiz"])
    p_rec.add_argument("--actual", required=True, type=Path, help="console export file")

    args = parser.parse_args(argv)

    try:
        state = desired_state(args.registry)
    except (RegistryError, OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2

    if args.command == "plan":
        plan = {
            "qualys_qid_exclusions": state["qualys"],
            "wiz_cve_ignore_rules": state["wiz"],
            "expired_do_not_sync": state["expired"],
        }
        print(json.dumps(plan, indent=2))
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        return 0

    try:
        actual = parse_actual(args.tool, args.actual)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read --actual: {exc}", file=sys.stderr)
        return 2

    diff = reconcile(args.tool, actual, state)
    label = {"qualys": "QID", "wiz": "CVE"}[args.tool]
    for identifier in diff["missing"]:
        print(f"MISSING   {label} {identifier}  ({state[args.tool][identifier]}) — add to {args.tool}")
    for identifier in diff["expired"]:
        print(
            f"EXPIRED   {label} {identifier}  ({state['expired'][args.tool][identifier]}) — "
            f"remove from {args.tool}; registry rule lapsed"
        )
    for identifier in diff["unmanaged"]:
        print(
            f"UNMANAGED {label} {identifier} — suppressed in {args.tool} with NO registry "
            "rule: unaudited risk acceptance, adopt it into the registry or remove it"
        )
    print(
        f"summary: {len(diff['managed'])} managed, {len(diff['missing'])} missing, "
        f"{len(diff['expired'])} expired, {len(diff['unmanaged'])} unmanaged"
    )
    return 1 if diff["missing"] or diff["expired"] or diff["unmanaged"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
