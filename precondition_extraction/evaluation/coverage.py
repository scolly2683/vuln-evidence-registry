#!/usr/bin/env python3
"""Per-CNA applicability coverage over CISA KEV — the measurement, not the extractor.

    python3 coverage.py            # print the tables
    python3 coverage.py --csv      # also write data/coverage_by_cna.csv

CVE 5.x has a `configurations` container meaning "configurations required for exploiting this
vulnerability" — the applicability data a defender actually needs. This counts how often CNAs
fill it, and what it is worth when they do.

Deterministic and offline. Two committed inputs, no network:
  data/kev_cvelist_scan_2026-09-02.json   1,687 KEV CVEs, container lengths per CVE
  ../pipeline/runs/edge-2023plus/*.yaml   the 170-CVE extraction run, for yield
  ../pipeline/data/inputs.json            which of those had a container in their text

The yield comparison is confounded with text length BY CONSTRUCTION — the container *is* the
extra text. That is the mechanism, not a bias. The confound that would matter is CNA identity
(maybe Palo Alto simply writes better advisories), so the within-CNA table below holds the
assigner fixed and asks the same question.
"""
from __future__ import annotations

import argparse
import collections
import csv
import glob
import json
import os
import pathlib
import statistics as st
import sys

import yaml

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
from agreement import wilson  # noqa: E402 — one implementation of the interval

SCAN = HERE / "data" / "kev_cvelist_scan_2026-09-02.json"
RUN = HERE.parent / "pipeline" / "runs" / "edge-2023plus"
INPUTS = HERE.parent / "pipeline" / "data" / "inputs.json"
MIN_N = 10  # a rate on fewer than ten records is not a rate


def pct(k: int, n: int) -> str:
    if not n:
        return "—"
    lo, hi = wilson(k, n)
    return f"{k/n:5.1%}  [{lo:.0%}, {hi:.0%}]"


def load_run() -> list[dict]:
    """Per-CVE gate counts from the 170-run, joined to container presence and CNA."""
    inputs = json.loads(INPUTS.read_text())
    scan = {x["cve"]: x for x in json.loads(SCAN.read_text())}
    rows = []
    for p in sorted(glob.glob(str(RUN / "CVE-*.yaml"))):
        cve = os.path.basename(p)[:-5]
        rec = yaml.safe_load(open(p, encoding="utf-8"))
        e = inputs.get(cve, {})
        rows.append({
            "cve": cve,
            "gates": len((rec.get("expected") or {}).get("preconditions") or []),
            "container": bool(e.get("has_configurations")),
            "cna": (scan.get(cve) or {}).get("cna"),
            "textlen": len(e.get("text") or ""),
        })
    return rows


def yield_row(label: str, rows: list[dict]) -> str:
    if not rows:
        return f"| {label} | 0 | — | — |"
    empty = sum(1 for r in rows if r["gates"] == 0)
    return (f"| {label} | {len(rows)} | {st.mean(r['gates'] for r in rows):.2f} | "
            f"{empty}/{len(rows)} ({empty/len(rows):.0%}) |")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", action="store_true")
    a = ap.parse_args()

    scan = json.loads(SCAN.read_text())
    n = len(scan)

    print(f"# Applicability coverage across CISA KEV (n={n}, catalogue 2026.08.31)\n")
    print("## How often is the field filled at all?\n")
    print("| container | filled | rate (Wilson 95%) |")
    print("|---|---|---|")
    for key, label in (("configurations_len", "CNA `configurations`"),
                       ("workarounds_len", "CNA `workarounds`"),
                       ("solutions_len", "CNA `solutions`"),
                       ("exploits_len", "CNA `exploits`"),
                       ("adp_conf_len", "ADP (CISA Vulnrichment) configurations+workarounds")):
        k = sum(1 for x in scan if x.get(key))
        print(f"| {label} | {k} | {pct(k, n)} |")

    print("\n## Per CNA (n >= %d KEV entries), by configurations rate\n" % MIN_N)
    print("| CNA | KEV entries | configurations | workarounds | solutions | median desc chars |")
    print("|---|---|---|---|---|---|")
    by = collections.Counter(x["cna"] for x in scan)
    table = []
    for cna, tot in by.items():
        if tot < MIN_N:
            continue
        rows = [x for x in scan if x["cna"] == cna]
        table.append((
            sum(1 for x in rows if x["configurations_len"]) / tot, cna, tot,
            sum(1 for x in rows if x["configurations_len"]),
            sum(1 for x in rows if x["workarounds_len"]),
            sum(1 for x in rows if x["solutions_len"]),
            int(st.median(x["desc_len"] for x in rows)),
        ))
    for _, cna, tot, c, w, s, dl in sorted(table, key=lambda t: (-t[0], -t[2])):
        print(f"| {cna} | {tot} | {pct(c, tot)} | {pct(w, tot)} | {pct(s, tot)} | {dl} |")
    small = sum(v for k, v in by.items() if v < MIN_N)
    print(f"\n{len(by)} CNAs in KEV; {len(table)} have >= {MIN_N} entries. "
          f"The remaining {small} entries sit with CNAs too small to rate.")

    print("\n## What the field is worth: gates extracted per CVE (the 170-CVE edge run)\n")
    run = load_run()
    print("| population | CVEs | mean gates/CVE | records stating no precondition |")
    print("|---|---|---|---|")
    print(yield_row("**all**, container filled", [r for r in run if r["container"]]))
    print(yield_row("**all**, not filled", [r for r in run if not r["container"]]))
    for cna in sorted({r["cna"] for r in run if r["container"] and r["cna"]}):
        same = [r for r in run if r["cna"] == cna]
        print(yield_row(f"{cna} only, container filled", [r for r in same if r["container"]]))
        print(yield_row(f"{cna} only, not filled", [r for r in same if not r["container"]]))

    print("\nThe per-CNA rows are the deconfound: same assigner, same product family, with and "
          "without the field.")

    if a.csv:
        out = HERE / "data" / "coverage_by_cna.csv"
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["cna", "kev_entries", "configurations", "workarounds", "solutions",
                        "median_desc_chars"])
            for _, cna, tot, c, wk, s, dl in sorted(table, key=lambda t: (-t[0], -t[2])):
                w.writerow([cna, tot, c, wk, s, dl])
        print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
