#!/usr/bin/env python3
"""Export the suppression registry as an OpenVEX document.

The registry's suppressions.yaml is the audited source of truth for
"this detection is wrong / not applicable here" verdicts. OpenVEX
(https://github.com/openvex/spec) is the industry interchange format for
exactly those statements — scanners (Grype, Trivy, Wiz-class tools)
consume it natively to suppress findings. This exporter makes the
registry the *author* of that format instead of a proprietary sidecar:

    python tools/export_vex.py --registry registry \
        --author "vuln-mgmt@example.org" --out export/openvex.json

Verdict → OpenVEX mapping:

    false_positive        -> not_affected  (default: component_not_present)
    not_applicable_config -> not_affected  (default: vulnerable_code_not_in_execute_path)
    risk_accepted         -> affected + action_statement

A suppression opts into VEX with an optional `vex:` block:

    vex:
      cve: CVE-2021-44228            # optional if match.cve_id is set
      products: ["pkg:maven/log4j/log4j"]   # REQUIRED — VEX speaks CVE x product
      justification: vulnerable_code_not_present   # optional; overrides default
      action_statement: "..."        # risk_accepted only; defaults from review_by

Rules that cannot be expressed in VEX (no CVE, or no products — e.g. a
QID-only false positive, which is scanner detection logic, not a product
statement) are skipped with a warning: those sync to the scanner's own
exclusion mechanism instead. The registry's `review_by` has no VEX field;
expiry stays a registry concern — an expired suppression drops out of the
next export.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from routing_registry.loader import RegistryError, load_registry  # noqa: E402

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# The fixed justification labels from the OpenVEX spec.
VALID_JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)

VERDICT_STATUS = {
    "false_positive": "not_affected",
    "not_applicable_config": "not_affected",
    "risk_accepted": "affected",
}
DEFAULT_JUSTIFICATION = {
    "false_positive": "component_not_present",
    "not_applicable_config": "vulnerable_code_not_in_execute_path",
}


class VexExportError(ValueError):
    """A suppression declares a vex block the exporter cannot translate."""


def _cves_for(entry: dict) -> list[str]:
    """CVE ids for the statement: vex.cve wins, else match.cve_id."""
    vex = entry.get("vex") or {}
    if "cve" in vex:
        value = vex["cve"]
        return value if isinstance(value, list) else [value]
    match_cves = (entry.get("match") or {}).get("cve_id")
    if match_cves:
        return match_cves if isinstance(match_cves, list) else [match_cves]
    return []


def statements_for(entry: dict) -> tuple[list[dict], str | None]:
    """OpenVEX statements for one suppression, or (nothing, why-skipped)."""
    verdict = entry.get("verdict")
    if verdict not in VERDICT_STATUS:
        return [], f"verdict {verdict!r} has no VEX mapping"

    vex = entry.get("vex") or {}
    cves = _cves_for(entry)
    if not cves:
        return [], "no CVE (QID-only rules sync to the scanner's own exclusions, not VEX)"
    products = vex.get("products") or []
    if not products:
        return [], "no vex.products — VEX statements are per CVE x product"

    provenance = entry.get("provenance") or {}
    status = VERDICT_STATUS[verdict]
    statements = []
    for cve in cves:
        statement: dict = {
            "vulnerability": {"name": cve},
            "products": [{"@id": p} for p in products],
            "status": status,
        }
        if status == "not_affected":
            justification = vex.get("justification") or DEFAULT_JUSTIFICATION[verdict]
            if justification not in VALID_JUSTIFICATIONS:
                raise VexExportError(
                    f"rule {entry.get('id')}: justification {justification!r} is not an "
                    f"OpenVEX label {VALID_JUSTIFICATIONS}"
                )
            statement["justification"] = justification
            if provenance.get("evidence"):
                statement["impact_statement"] = str(provenance["evidence"]).strip()
        else:  # affected (risk_accepted)
            action = vex.get("action_statement") or (
                f"Risk accepted in the suppression registry "
                f"({entry.get('id')}); re-verify by {entry.get('review_by')}."
            )
            statement["action_statement"] = action
        if provenance.get("date"):
            statement["timestamp"] = f"{provenance['date']}T00:00:00Z"
        statements.append(statement)
    return statements, None


def export(
    registry_dir: Path,
    *,
    author: str,
    doc_id: str,
    timestamp: str,
    today: dt.date | None = None,
) -> tuple[dict, list[str]]:
    """Build the OpenVEX document. Returns (document, skip warnings).

    Suppressions past review_by are excluded — an expired suppression must
    not keep silencing scanners — and reported in the warnings.
    """
    load_registry(registry_dir)  # RegistryError on structural problems
    today = today or dt.date.today()

    entries = yaml.safe_load(
        (registry_dir / "rules" / "suppressions.yaml").read_text(encoding="utf-8")
    ) or []

    statements: list[dict] = []
    warnings: list[str] = []
    for entry in entries:
        review_by = entry.get("review_by")
        if review_by and dt.date.fromisoformat(str(review_by)) < today:
            warnings.append(
                f"{entry.get('id')}: past review_by {review_by} — EXCLUDED from the "
                "export until re-verified"
            )
            continue
        stmts, skipped = statements_for(entry)
        if skipped:
            warnings.append(f"{entry.get('id')}: not exported ({skipped})")
        statements.extend(stmts)

    document = {
        "@context": OPENVEX_CONTEXT,
        "@id": doc_id,
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "tooling": "vuln-evidence-registry/tools/export_vex.py",
        "statements": statements,
    }
    return document, warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--registry", default=Path("registry"), type=Path)
    parser.add_argument("--out", default=Path("export/openvex.json"), type=Path)
    parser.add_argument("--author", required=True,
                        help="document author, e.g. team mailbox or org IRI")
    parser.add_argument("--doc-id", default=None,
                        help="document @id IRI (default derived from author + date)")
    parser.add_argument("--timestamp", default=None,
                        help="RFC3339 document timestamp (default: now UTC)")
    args = parser.parse_args(argv)

    timestamp = args.timestamp or dt.datetime.now(dt.timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    doc_id = args.doc_id or f"urn:vex:{args.author}:{timestamp[:10]}"

    try:
        document, warnings = export(
            args.registry, author=args.author, doc_id=doc_id, timestamp=timestamp
        )
    except (RegistryError, VexExportError) as exc:
        print(exc, file=sys.stderr)
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"{args.out}: {len(document['statements'])} statements")
    for warning in warnings:
        print(f"WARN: {warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
