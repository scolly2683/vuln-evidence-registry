"""CLI: route findings, validate the registry, propose corrections.

    python -m routing_registry validate  --registry registry
    python -m routing_registry route     --registry registry --findings f.jsonl --stats
    python -m routing_registry propose-correction --registry registry \\
        --route euc-user-installed --match product="visual studio" \\
        --context bundle_member=false --decided-by you \\
        --trigger "survived 2 patch cycles"
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from .corrections import propose_correction
from .loader import RegistryError, load_registry
from .router import route_all, stats


def _read_findings(path: Path) -> list[dict]:
    if path.suffix == ".csv":
        with path.open(newline="", encoding="utf-8") as fh:
            return [dict(row) for row in csv.DictReader(fh)]
    findings = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            findings.append(json.loads(line))
    return findings


def _parse_kv(pairs: list[str]) -> dict:
    """k=v pairs; comma in v makes a list; true/false become booleans."""
    out: dict = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            raise SystemExit(f"expected key=value, got {pair!r}")
        if "," in value:
            out[key] = [v.strip() for v in value.split(",")]
        elif value.lower() in ("true", "false"):
            out[key] = value.lower() == "true"
        else:
            out[key] = value
    return out


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--registry", default="registry", help="registry directory")

    parser = argparse.ArgumentParser(prog="routing-registry")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", parents=[common], help="validate registry structure and freshness")

    p_route = sub.add_parser("route", parents=[common], help="route findings (JSONL or CSV)")
    p_route.add_argument("--findings", required=True, type=Path)
    p_route.add_argument("--stats", action="store_true", help="print summary to stderr")
    p_route.add_argument(
        "--unroutable-only", action="store_true", help="emit only the adjudication queue"
    )

    p_corr = sub.add_parser("propose-correction", parents=[common], help="append a learned correction")
    p_corr.add_argument("--route", required=True)
    p_corr.add_argument("--match", action="append", default=[], metavar="K=V")
    p_corr.add_argument("--context", action="append", default=[], metavar="K=V")
    p_corr.add_argument("--decided-by", required=True)
    p_corr.add_argument("--trigger", required=True)
    p_corr.add_argument("--evidence", default="")
    p_corr.add_argument("--review-by", default=None)
    p_corr.add_argument("--note", default="")
    p_corr.add_argument(
        "--fixture-finding", type=Path, default=None,
        help="JSON file of the triggering finding; becomes a regression fixture",
    )

    args = parser.parse_args(argv)

    try:
        registry = load_registry(args.registry)
    except RegistryError as exc:
        print(exc, file=sys.stderr)
        return 2

    if args.command == "validate":
        counts = {k: len(registry.rules_of_kind(k)) for k in ("screen", "identity", "correction")}
        print(
            f"OK: {len(registry.channels)} channels, "
            f"{counts['screen']} screens, {counts['identity']} identity rules, "
            f"{counts['correction']} corrections"
        )
        for warning in registry.warnings:
            print(f"WARN: {warning}")
        return 0

    if args.command == "route":
        findings = _read_findings(args.findings)
        results = route_all(findings, registry)
        for result in results:
            if args.unroutable_only and result.disposition != "unroutable":
                continue
            print(json.dumps(result.to_dict()))
        if args.stats:
            print(json.dumps(stats(results), indent=2), file=sys.stderr)
        return 0

    if args.command == "propose-correction":
        fixture = None
        if args.fixture_finding:
            fixture = json.loads(args.fixture_finding.read_text(encoding="utf-8"))
        try:
            rule_id = propose_correction(
                args.registry,
                route=args.route,
                match=_parse_kv(args.match),
                context=_parse_kv(args.context),
                decided_by=args.decided_by,
                trigger=args.trigger,
                evidence=args.evidence,
                review_by=args.review_by,
                note=args.note,
                fixture_finding=fixture,
            )
        except (ValueError, RegistryError) as exc:
            print(exc, file=sys.stderr)
            return 2
        print(f"appended {rule_id} — commit it as a reviewable diff")
        return 0

    return 1  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
