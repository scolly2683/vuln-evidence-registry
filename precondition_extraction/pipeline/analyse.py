#!/usr/bin/env python3
"""Bucket an extraction run's preconditions into the families the ledger is built on.

    python3 analyse.py --run runs/edge-2023plus [--json out.json]

Two questions this exists to answer, both of them the whole point of extracting gates at
all rather than reading CVSS:

  1. **How many exploited CVEs require the attacker to already hold something?**
     Credentials, an account, local access, a prior compromise. These are the CVEs where
     "internet-facing and unpatched" is the wrong mental model — something else has to go
     wrong first. On the 50-record sample this was ~25%.

  2. **How many are gated on one exposed management surface?** A portal, a gateway, an
     admin interface, a VPN endpoint. On the 50-record sample, one gate ("remote-access
     portal exposed") sat behind 7 of 20 edge CVEs — which is the finding that makes a
     controls ledger worth building: one control, many CVEs.

Bucketing is keyword-based over the precondition id + statement, and it is REPORTED AS
SUCH. It is a triage aid for reading, not a measurement: `--json` writes the per-CVE
assignments so any number quoted from here can be checked against the records. Anything
unmatched is printed rather than silently dropped, because the unmatched pile is where the
next family comes from.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

import yaml

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
from families import family  # noqa: E402  — the one implementation; see families.py


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()
    run = pathlib.Path(a.run)
    if not run.is_absolute():
        run = HERE / run
    files = sorted(run.glob("CVE-*.yaml"))
    if not files:
        raise SystemExit(f"error: no records in {run}")

    fam = collections.Counter()
    cat = collections.Counter()
    per_cve: dict[str, dict] = {}
    empty, total_pc, unmatched = [], 0, []
    holds, surface = set(), set()

    for p in files:
        rec = yaml.safe_load(p.read_text(encoding="utf-8"))
        cve = rec["cve_id"]
        pcs = (rec.get("expected") or {}).get("preconditions") or []
        total_pc += len(pcs)
        if not pcs:
            empty.append(cve)
        fams = []
        for pc in pcs:
            f = family(pc)
            fam[f] += 1
            cat[pc.get("category")] += 1
            fams.append(f)
            if f == "other":
                unmatched.append((cve, pc.get("id"), (pc.get("statement") or "")[:80]))
            if f == "attacker-already-holds":
                holds.add(cve)
            if f == "management-surface-exposed":
                surface.add(cve)
        per_cve[cve] = {"n": len(pcs), "families": fams,
                        "vendor": (rec.get("expected") or {}).get("identity", {}).get("vendor")}

    n = len(files)
    print(f"# Extraction run: {run.name}\n")
    print(f"{n} CVEs, {total_pc} preconditions, {total_pc / n:.2f} per CVE")
    print(f"{len(empty)} records ({len(empty) / n:.0%}) state no precondition\n")

    print("## Families (keyword bucketing — a reading aid, not a measurement)\n")
    for name, c in fam.most_common():
        print(f"  {name:32s} {c:5d}  {c / total_pc:5.1%}")

    print("\n## Categories (from the records, exact)\n")
    for name, c in cat.most_common():
        print(f"  {str(name):32s} {c:5d}  {c / total_pc:5.1%}")

    print("\n## The two ledger questions\n")
    print(f"  attacker must already hold something : {len(holds):3d} / {n}  ({len(holds) / n:.0%})")
    print(f"  gated on an exposed management surface: {len(surface):3d} / {n}  ({len(surface) / n:.0%})")
    both = holds & surface
    print(f"  both                                  : {len(both):3d} / {n}  ({len(both) / n:.0%})")
    neither = n - len(holds | surface)
    print(f"  neither                               : {neither:3d} / {n}  ({neither / n:.0%})")

    print("\n## Exposed-management-surface CVEs by vendor\n")
    byv = collections.Counter(per_cve[c]["vendor"] for c in surface)
    for v, c in byv.most_common(15):
        print(f"  {str(v):28s} {c:3d}")

    if unmatched:
        print(f"\n## Other (no family) — {len(unmatched)} (where the next family comes from)\n")
        for cve, pid, stmt in unmatched[:25]:
            print(f"  {cve} | {pid} | {stmt}")
        if len(unmatched) > 25:
            print(f"  ... and {len(unmatched) - 25} more")

    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(
            {"run": run.name, "cves": n, "preconditions": total_pc,
             "empty": empty, "families": dict(fam), "categories": {str(k): v for k, v in cat.items()},
             "attacker_already_holds": sorted(holds), "management_surface": sorted(surface),
             "per_cve": per_cve}, indent=1))
        print(f"\nwrote {a.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
