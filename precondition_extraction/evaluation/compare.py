#!/usr/bin/env python3
"""Score a candidate extraction run against the verified reference records.

    python compare.py --cand records-groq [--ref records] [--out compare-groq.md]

The comparison key is the **cited sentence**. Rule 2 makes every precondition
rest on a verbatim sentence, so "did the candidate cite the same sentence the
reference did" is deterministic — no fuzzy judging, no LLM-as-judge. On top of
that, per CVE:

- ``cite_valid``  — candidate ``cites`` values that are substrings of the advisory
  text after whitespace/NBSP normalisation (the standard's hard rule, applied the
  way ``schema.citation_in_text`` applies it; byte-strict matching penalised models
  for turning U+00A0 into a space, which is not a different sentence).
- ``text_drift``  — candidate ``advisory_text`` differs from the reference's
  (the model altered the input it was told to copy verbatim).
- ``empty_agree`` — both empty or both non-empty.
- ``recall`` / ``precision`` at the sentence level (unique normalised cites).
- ``cat_agree``   — on matched sentences, the category multisets are equal.

Verdict thresholds for "the candidate model can follow the standard well enough
to run the full KEV catalogue": cite_valid >= 0.95, sentence recall >= 0.80,
empty_agree >= 0.90. Below any of them, read the per-CVE table before deciding.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
from agreement import wilson  # noqa: E402 — one implementation of the interval, not two


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").replace("\xa0", " ")).strip().strip('"“”').lower()


def load(d: pathlib.Path) -> dict[str, dict]:
    # Fail loudly on a directory that isn't there or holds no records. Path.glob on a missing
    # directory yields nothing rather than raising, so a mistyped --cand used to print a
    # complete, clean-looking table of zeros — a comparison that never happened, reported as
    # a comparison that found nothing wrong. That is the worst possible failure mode for a
    # conformance scorer, so it is now an error.
    if not d.is_dir():
        raise SystemExit(
            f"error: no such directory: {d}\n"
            f"       candidate runs live under {HERE / 'candidates'}/ — "
            f"pass e.g. --cand candidates/sonnet-r10"
        )
    out = {}
    for p in sorted(d.glob("*.yaml")):
        try:
            r = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as exc:
            out[p.stem] = {"_parse_error": str(exc)}
            continue
        out[p.stem] = r
    if not out:
        raise SystemExit(f"error: {d} contains no *.yaml records")
    return out


def pcs(r: dict) -> list[dict]:
    exp = r.get("expected", r) or {}
    return list(exp.get("preconditions") or [])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", default="reference")
    ap.add_argument("--cand", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    ref = load(HERE / args.ref)
    cand = load(HERE / args.cand)
    strata = {r["cveID"]: r["stratum"] for r in json.loads((HERE / "kev_sample.json").read_text())}
    # The held-out draw keys its strata differently (cve_id, not cveID) and lives elsewhere;
    # without this every held-out row bucketed to "?" and the per-stratum table was useless.
    heldout_sample = HERE / "heldout" / "sample.json"
    if heldout_sample.exists():
        strata.update({r["cve_id"]: r["stratum"] for r in json.loads(heldout_sample.read_text())})
    both = [c for c in ref if c in cand]
    missing = [c for c in ref if c not in cand]

    rows = []
    tot = collections.Counter()
    per_stratum: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for c in both:
        rr, cr = ref[c], cand[c]
        s = strata.get(c, "?")
        if "_parse_error" in cr:
            rows.append((c, s, "PARSE-FAIL", "", "", "", "", "", ""))
            tot["parse_fail"] += 1
            per_stratum[s]["parse_fail"] += 1
            continue
        ref_text = rr.get("advisory_text") or ""
        cand_text = cr.get("advisory_text") or ""
        drift = norm(ref_text) != norm(cand_text)
        rp, cp = pcs(rr), pcs(cr)
        cand_cites = [p.get("cites") or "" for p in cp]
        valid = sum(1 for x in cand_cites if x and norm(x) in norm(ref_text))  # same normalisation as schema.citation_in_text
        ref_set = {norm(p.get("cites")) for p in rp if p.get("cites")}
        cand_set = {norm(x) for x in cand_cites if x}
        inter = ref_set & cand_set
        recall = len(inter) / len(ref_set) if ref_set else None
        precision = len(inter) / len(cand_set) if cand_set else None

        # CONTAINMENT match, reported alongside the exact key because the exact key has a
        # measured defect: two annotators who find the SAME gate score zero overlap if one
        # quotes the whole sentence and the other the precise clause. Measured on the
        # held-out run 2026-09-03 — CVE-2016-8735, both annotators finding
        # "JmxRemoteLifecycleListener is used" and "an attacker can reach JMX ports", scored
        # exact-recall 0.00 because the reference quoted the enclosing sentence for both.
        # Neither number is "the" answer: exact is a LOWER bound on gate agreement (it
        # punishes span choice), containment is an UPPER bound (a long sentence can swallow
        # an unrelated clause inside it). Report both, and never quote one alone.
        inter_c = {a for a in ref_set if any(a in b or b in a for b in cand_set)}
        inter_c_rev = {b for b in cand_set if any(a in b or b in a for a in ref_set)}
        recall_c = len(inter_c) / len(ref_set) if ref_set else None
        empty_agree = (not rp) == (not cp)
        # category agreement on matched sentences
        cat_ok = cat_n = 0
        for sent in inter:
            rc = sorted(p.get("category") for p in rp if norm(p.get("cites")) == sent)
            cc = sorted(p.get("category") for p in cp if norm(p.get("cites")) == sent)
            cat_n += 1
            cat_ok += rc == cc
        rows.append((c, s, len(rp), len(cp), f"{valid}/{len(cand_cites)}",
                     "" if recall is None else f"{recall:.2f}",
                     "" if precision is None else f"{precision:.2f}",
                     "✓" if empty_agree else "✗", "drift" if drift else ""))
        for bucket in (tot, per_stratum[s]):
            bucket["cves"] += 1
            bucket["ref_pcs"] += len(rp)
            bucket["cand_pcs"] += len(cp)
            bucket["cites"] += len(cand_cites)
            bucket["cites_valid"] += valid
            bucket["ref_sent"] += len(ref_set)
            bucket["cand_sent"] += len(cand_set)
            bucket["inter"] += len(inter)
            bucket["inter_c"] += len(inter_c)
            bucket["inter_c_rev"] += len(inter_c_rev)
            bucket["empty_agree"] += empty_agree
            bucket["drift"] += drift
            bucket["cat_n"] += cat_n
            bucket["cat_ok"] += cat_ok

    def summarise(b: collections.Counter) -> dict:
        return {
            "cves": b["cves"],
            "ref_pcs": b["ref_pcs"], "cand_pcs": b["cand_pcs"],
            "cite_valid": b["cites_valid"] / b["cites"] if b["cites"] else None,
            "recall": b["inter"] / b["ref_sent"] if b["ref_sent"] else None,
            "precision": b["inter"] / b["cand_sent"] if b["cand_sent"] else None,
            "recall_c": b["inter_c"] / b["ref_sent"] if b["ref_sent"] else None,
            "precision_c": b["inter_c_rev"] / b["cand_sent"] if b["cand_sent"] else None,
            "empty_agree": b["empty_agree"] / b["cves"] if b["cves"] else None,
            "cat_agree": b["cat_ok"] / b["cat_n"] if b["cat_n"] else None,
            "drift": b["drift"], "parse_fail": b["parse_fail"],
        }

    def fmt(v):
        return "—" if v is None else (f"{v:.2f}" if isinstance(v, float) else str(v))

    out = [f"# Comparison: `{args.cand}` vs reference `{args.ref}`\n",
           f"{len(both)} CVEs compared, {len(missing)} missing from candidate"
           + (f" ({', '.join(missing)})" if missing else "") + ".\n",
           "| scope | CVEs | ref #pre | cand #pre | cite_valid | recall (exact) | recall (cont.) | "
           "precision (exact) | precision (cont.) | empty_agree | cat_agree | drift | parse_fail |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, b in [("**all**", tot)] + sorted(per_stratum.items()):
        s = summarise(b)
        out.append(f"| {name} | {s['cves']} | {s['ref_pcs']} | {s['cand_pcs']} | {fmt(s['cite_valid'])} | "
                   f"{fmt(s['recall'])} | {fmt(s['recall_c'])} | {fmt(s['precision'])} | {fmt(s['precision_c'])} | "
                   f"{fmt(s['empty_agree'])} | {fmt(s['cat_agree'])} | {s['drift']} | {s['parse_fail']} |")
    # Wilson 95% intervals on the three gated proportions. A point estimate on 30 CVEs and
    # ~40 gates is a soft number and reporting it bare invites a false read of precision:
    # at these counts the interval on recall is worth ±0.15, and per stratum nearer ±0.25.
    # Every headline figure carries its interval or it is not a headline figure.
    out.append("\n## 95% intervals (Wilson)\n")
    out.append("| scope | recall (exact) | recall (cont.) | precision (exact) | empty_agree |")
    out.append("|---|---|---|---|---|")
    for name, b in [("**all**", tot)] + sorted(per_stratum.items()):
        cells = []
        for num, den in (("inter", "ref_sent"), ("inter_c", "ref_sent"),
                         ("inter", "cand_sent"), ("empty_agree", "cves")):
            ci = wilson(b[num], b[den])
            cells.append("—" if ci is None else f"{b[num]}/{b[den]}  [{ci[0]:.2f}, {ci[1]:.2f}]")
        out.append(f"| {name} | " + " | ".join(cells) + " |")

    s = summarise(tot)
    ok = all([(s["cite_valid"] or 0) >= 0.95, (s["recall"] or 0) >= 0.80, (s["empty_agree"] or 0) >= 0.90])
    out.append(f"\n**Verdict:** {'ACCEPTABLE for the full run' if ok else 'NOT acceptable as-is'} "
               f"(thresholds: cite_valid ≥0.95, recall ≥0.80, empty_agree ≥0.90).")
    lo_hi = wilson(tot["inter"], tot["ref_sent"])
    if lo_hi:
        out.append(f"A verdict read off a point estimate is a verdict on the midpoint of "
                   f"[{lo_hi[0]:.2f}, {lo_hi[1]:.2f}] — read the interval before acting on the word above.\n")
    out.append("## Per CVE\n")
    out.append("| CVE | stratum | ref #pre | cand #pre | cand cites valid | recall | precision | empty agree | note |")
    out.append("|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    text = "\n".join(out) + "\n"
    if args.out:
        (HERE / args.out).write_text(text)
    print(text)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
