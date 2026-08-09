#!/usr/bin/env python3
"""Flatten the routing registry YAML into DB-loadable CSVs.

The YAML registry in git is canonical; the database that feeds BI gets
GENERATED rule tables (truncate-and-reload, never hand-edited) plus the
regression fixtures as data for the SQL parity gate. One generic routing
view interprets the tables, so a rules change in git needs no SQL change.
See docs/sql-powerbi.md for the table DDL, the routing view, and the gate.

    python tools/export_registry_sql.py \
        --registry registry --fixtures fixtures/regression.yaml --out export

Outputs (column order matches the DDL in docs/sql-powerbi.md):
    channels.csv                -> reg.channels
    rules.csv                   -> reg.rules
    rule_predicates.csv         -> reg.rule_predicates
    fixtures.csv                -> reg.fixtures
    fixture_findings.csv        -> vm.findings        (fixture rows only)
    fixture_finding_context.csv -> vm.finding_context (fixture rows only)

The exporter validates the registry first and refuses to export anything the
SQL routing view cannot faithfully evaluate — a mistranslated rule that
routes differently in SQL than in Python is strictly worse than a loud
failure here.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from routing_registry.loader import RegistryError, load_registry  # noqa: E402

# Subject predicate types the SQL routing view implements. Must stay in sync
# with the view in docs/sql-powerbi.md and router._match_subject.
SUBJECT_PRED_TYPES = (
    "cna",
    "vendor",
    "product",
    "package",
    "source",
    "nvd_status",
    "cve_id",   # EXACT equality in SQL — no CHARINDEX/contained semantics
    "qid",      # EXACT equality in SQL
    "purl_prefix",
    "keywords",
)

CHANNEL_COLUMNS = ("channel_id", "channel_name", "cadence", "cadence_type", "owner_group")
RULE_COLUMNS = (
    "rule_id",
    "kind",
    "priority",
    "route_channel_id",
    "screen_action",
    "park_queue",
    "verdict",
    "review_by",
    "decided_by",
    "decided_on",
    "trigger_note",
)
PREDICATE_COLUMNS = ("rule_id", "pred_type", "pred_key", "pred_value")
FIXTURE_COLUMNS = (
    "fixture_name",
    "finding_id",
    "expected_disposition",
    "expected_channel_id",
    "expected_rule_id",
)
FINDING_COLUMNS = (
    "finding_id",
    "cve_id",
    "cna",
    "vendor",
    "product",
    "package",
    "purl",
    "description",
    "nvd_status",
    "source",
    "qid",
)


class ExportError(ValueError):
    """A registry construct with no faithful SQL translation."""


def _norm_value(value: object) -> str:
    """Booleans export as lowercase 'true'/'false' — the string form context
    values take in vm.finding_context. Everything else exports verbatim
    (including deliberate whitespace in keyword values like ' plc ')."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def flatten_rule(entry: dict, kind: str) -> tuple[dict, list[dict]]:
    """One YAML rule -> one rules.csv row + N rule_predicates.csv rows.

    Predicate semantics carried by the flat shape: rows of the same
    (pred_type, pred_key) group are OR'd; distinct groups are AND'd.
    """
    rule_id = entry["id"]
    provenance = entry.get("provenance") or {}
    row = {
        "rule_id": rule_id,
        "kind": kind,
        "priority": int(entry.get("priority", 100)),
        "route_channel_id": entry.get("route") or "",
        "screen_action": entry.get("action") or "",
        "park_queue": entry.get("queue") or "",
        "verdict": entry.get("verdict") or "",
        "review_by": entry.get("review_by") or "",
        "decided_by": provenance.get("decided_by", ""),
        "decided_on": provenance.get("date", ""),
        "trigger_note": provenance.get("trigger", ""),
    }

    predicates: list[dict] = []
    for pred_type, value in (entry.get("match") or {}).items():
        if pred_type not in SUBJECT_PRED_TYPES:
            raise ExportError(
                f"rule {rule_id}: match field {pred_type!r} is not implemented by the "
                "SQL routing view — extend the view and SUBJECT_PRED_TYPES together"
            )
        values = value if isinstance(value, list) else [value]
        for v in values:
            predicates.append(
                {"rule_id": rule_id, "pred_type": pred_type, "pred_key": "", "pred_value": _norm_value(v)}
            )

    for key, value in (entry.get("context") or {}).items():
        if isinstance(value, dict):
            if set(value) == {"in"}:
                for v in value["in"]:
                    predicates.append(
                        {"rule_id": rule_id, "pred_type": "context", "pred_key": key, "pred_value": _norm_value(v)}
                    )
            else:
                raise ExportError(
                    f"rule {rule_id}: context operator {sorted(set(value) - {'in'})} on {key!r} "
                    "has no SQL translation yet — extend the exporter and the routing view together"
                )
        else:
            predicates.append(
                {"rule_id": rule_id, "pred_type": "context", "pred_key": key, "pred_value": _norm_value(value)}
            )

    return row, predicates


def flatten_fixture(entry: dict) -> tuple[dict, dict, list[dict]]:
    """One fixture -> fixtures.csv row + finding row + context rows."""
    name = entry["name"]
    finding = entry.get("finding") or {}
    expect = entry.get("expect") or {}
    finding_id = str(finding.get("id") or finding.get("finding_id") or name)

    fixture_row = {
        "fixture_name": name,
        "finding_id": finding_id,
        "expected_disposition": expect.get("disposition", ""),
        "expected_channel_id": expect.get("channel", "") or "",
        "expected_rule_id": expect.get("rule_id", "") or "",
    }
    finding_row = {"finding_id": finding_id}
    for column in FINDING_COLUMNS[1:]:
        finding_row[column] = _norm_value(finding.get(column, "") or "")
    context_rows = [
        {"finding_id": finding_id, "context_key": key, "context_value": _norm_value(value)}
        for key, value in (finding.get("context") or {}).items()
    ]
    return fixture_row, finding_row, context_rows


def _load_yaml_list(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return yaml.safe_load(path.read_text(encoding="utf-8")) or []


def _write_csv(path: Path, columns: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def export(registry_dir: Path, fixtures_path: Path, out_dir: Path) -> dict[str, int]:
    """Validate, flatten, and write all CSVs. Returns row counts per file."""
    load_registry(registry_dir)  # RegistryError on structural problems

    channel_rows = [
        {
            "channel_id": ch["id"],
            "channel_name": ch.get("name", ch["id"]),
            "cadence": ch.get("cadence", ""),
            "cadence_type": ch.get("cadence_type", "ad_hoc"),
            "owner_group": ch.get("owner", "UNASSIGNED"),
        }
        for ch in _load_yaml_list(registry_dir / "channels.yaml")
    ]

    rule_rows: list[dict] = []
    predicate_rows: list[dict] = []
    for filename, kind in (
        (Path("rules") / "suppressions.yaml", "suppression"),
        ("screens.yaml", "screen"),
        (Path("rules") / "identity.yaml", "identity"),
        (Path("rules") / "corrections.yaml", "correction"),
    ):
        for entry in _load_yaml_list(registry_dir / filename):
            row, predicates = flatten_rule(entry, kind)
            rule_rows.append(row)
            predicate_rows.extend(predicates)

    fixture_rows: list[dict] = []
    finding_rows: dict[str, dict] = {}
    context_rows: list[dict] = []
    seen_context: set[tuple[str, str]] = set()
    for entry in _load_yaml_list(fixtures_path):
        fixture_row, finding_row, ctx = flatten_fixture(entry)
        fixture_rows.append(fixture_row)
        existing = finding_rows.get(finding_row["finding_id"])
        if existing is not None and existing != finding_row:
            raise ExportError(
                f"fixtures reuse finding id {finding_row['finding_id']!r} with different content"
            )
        finding_rows[finding_row["finding_id"]] = finding_row
        for row in ctx:
            key = (row["finding_id"], row["context_key"])
            if key not in seen_context:
                seen_context.add(key)
                context_rows.append(row)

    out_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "channels.csv": (CHANNEL_COLUMNS, channel_rows),
        "rules.csv": (RULE_COLUMNS, rule_rows),
        "rule_predicates.csv": (PREDICATE_COLUMNS, predicate_rows),
        "fixtures.csv": (FIXTURE_COLUMNS, fixture_rows),
        "fixture_findings.csv": (FINDING_COLUMNS, list(finding_rows.values())),
        "fixture_finding_context.csv": (("finding_id", "context_key", "context_value"), context_rows),
    }
    counts = {}
    for filename, (columns, rows) in outputs.items():
        _write_csv(out_dir / filename, columns, rows)
        counts[filename] = len(rows)
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--registry", default="registry", type=Path)
    parser.add_argument("--fixtures", default=Path("fixtures/regression.yaml"), type=Path)
    parser.add_argument("--out", default=Path("export"), type=Path)
    args = parser.parse_args(argv)

    try:
        counts = export(args.registry, args.fixtures, args.out)
    except (RegistryError, ExportError) as exc:
        print(exc, file=sys.stderr)
        return 2
    for filename, count in counts.items():
        print(f"{args.out / filename}: {count} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
