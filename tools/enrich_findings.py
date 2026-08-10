#!/usr/bin/env python3
"""Tier-0 enrichment: tag findings with exploitation intel, no asset contact.

This is a BACKEND job — it runs on a schedule (you / engineering own it),
NOT something an analyst runs. Its whole purpose is to make the analyst
queue arrive pre-sorted so a non-coder only ever reviews a short,
already-prioritised list.

For each finding it adds four facts and one band, all from free feeds:

    kev              in CISA Known Exploited Vulnerabilities (confirmed
                     exploited in the wild)
    epss             EPSS probability of exploitation in the next 30 days
    epss_percentile  EPSS percentile
    poc_public       public exploit code exists (nomi-sec / trickest feed)
    triage_band      act_now | verify | standard   (see below)

    act_now  : kev, or epss >= 0.30  — real, urgent; route now regardless of cycle
    verify   : poc_public, or epss >= 0.10 — worth an exploitability check (tier 1/2)
    standard : everything else — rides the normal cycle

Thresholds mirror pattern 1 (EVIDENCE gate 0.10, act-now 0.30) so the whole
repo speaks one language.

OFFLINE by design — reads snapshot files so it works behind a proxy and in
CI; the scheduled job refreshes the snapshots. Snapshot sources:
    --kev   CISA KEV JSON   (known_exploited_vulnerabilities.json)
    --epss  FIRST EPSS CSV  (epss_scores-YYYY-MM-DD.csv[.gz-extracted])
    --poc   newline list of CVE ids (export from nomi-sec PoC-in-GitHub /
            trickest/cve)

    python tools/enrich_findings.py --findings month.jsonl \
        --kev kev.json --epss epss.csv --poc poc.txt --out enriched.jsonl --stats
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

EVIDENCE_EPSS = 0.10   # matches vuln_evidence_registry EPSS_THRESHOLD
ACT_NOW_EPSS = 0.30    # matches vuln_evidence_registry ACT_NOW_EPSS_THRESHOLD


def load_kev(path: Path | None) -> set[str]:
    if not path:
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    # CISA format: {"vulnerabilities": [{"cveID": "CVE-..."}]}. Also accept a
    # bare list of ids for convenience.
    if isinstance(data, dict):
        return {v["cveID"].upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
    return {str(v).upper() for v in data}


def load_epss(path: Path | None) -> dict[str, tuple[float, float]]:
    """cve -> (epss, percentile). FIRST CSV has a leading #comment line."""
    if not path:
        return {}
    scores: dict[str, tuple[float, float]] = {}
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
    for row in csv.DictReader(lines):
        cve = (row.get("cve") or "").upper()
        if not cve:
            continue
        try:
            scores[cve] = (float(row.get("epss", 0)), float(row.get("percentile", 0)))
        except ValueError:
            continue
    return scores


def load_poc(path: Path | None) -> set[str]:
    if not path:
        return set()
    return {
        ln.strip().upper()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    }


def band(kev: bool, epss: float | None, poc: bool) -> str:
    if kev or (epss is not None and epss >= ACT_NOW_EPSS):
        return "act_now"
    if poc or (epss is not None and epss >= EVIDENCE_EPSS):
        return "verify"
    return "standard"


def enrich_one(finding: dict, kev: set[str], epss: dict, poc: set[str]) -> dict:
    cve = str(finding.get("cve_id") or "").upper()
    is_kev = cve in kev
    score = epss.get(cve)
    epss_value = score[0] if score else None
    is_poc = cve in poc
    return {
        **finding,
        "kev": is_kev,
        "epss": epss_value,
        "epss_percentile": score[1] if score else None,
        "poc_public": is_poc,
        "triage_band": band(is_kev, epss_value, is_poc),
    }


def enrich_all(findings: list[dict], kev: set[str], epss: dict, poc: set[str]) -> list[dict]:
    return [enrich_one(f, kev, epss, poc) for f in findings]


def _read_findings(path: Path) -> list[dict]:
    if path.suffix == ".csv":
        with path.open(newline="", encoding="utf-8") as fh:
            return [dict(row) for row in csv.DictReader(fh)]
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--kev", type=Path, default=None)
    parser.add_argument("--epss", type=Path, default=None)
    parser.add_argument("--poc", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None, help="default stdout")
    parser.add_argument("--stats", action="store_true")
    args = parser.parse_args(argv)

    try:
        findings = _read_findings(args.findings)
        kev, epss, poc = load_kev(args.kev), load_epss(args.epss), load_poc(args.poc)
    except (OSError, json.JSONDecodeError) as exc:
        print(exc, file=sys.stderr)
        return 2

    enriched = enrich_all(findings, kev, epss, poc)
    lines = "\n".join(json.dumps(f) for f in enriched)
    if args.out:
        args.out.write_text(lines + "\n", encoding="utf-8")
    else:
        print(lines)

    if args.stats:
        bands: dict[str, int] = {}
        for f in enriched:
            bands[f["triage_band"]] = bands.get(f["triage_band"], 0) + 1
        summary = {"total": len(enriched), "by_band": bands,
                   "kev": sum(1 for f in enriched if f["kev"]),
                   "poc_public": sum(1 for f in enriched if f["poc_public"])}
        print(json.dumps(summary, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
