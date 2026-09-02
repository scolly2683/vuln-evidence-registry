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

import yaml

HERE = pathlib.Path(__file__).parent


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").replace("\xa0", " ")).strip().strip('"“”').lower()


def load(d: pathlib.Path) -> dict[str, dict]:
    out = {}
    for p in sorted(d.glob("*.yaml")):
        try:
            r = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as exc:
            out[p.stem] = {"_parse_error": str(exc)}
            continue
        out[p.stem] = r
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
            "empty_agree": b["empty_agree"] / b["cves"] if b["cves"] else None,
            "cat_agree": b["cat_ok"] / b["cat_n"] if b["cat_n"] else None,
            "drift": b["drift"], "parse_fail": b["parse_fail"],
        }

    def fmt(v):
        return "—" if v is None else (f"{v:.2f}" if isinstance(v, float) else str(v))

    out = [f"# Comparison: `{args.cand}` vs reference `{args.ref}`\n",
           f"{len(both)} CVEs compared, {len(missing)} missing from candidate"
           + (f" ({', '.join(missing)})" if missing else "") + ".\n",
           "| scope | CVEs | ref #pre | cand #pre | cite_valid | recall | precision | empty_agree | cat_agree | drift | parse_fail |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, b in [("**all**", tot)] + sorted(per_stratum.items()):
        s = summarise(b)
        out.append(f"| {name} | {s['cves']} | {s['ref_pcs']} | {s['cand_pcs']} | {fmt(s['cite_valid'])} | "
                   f"{fmt(s['recall'])} | {fmt(s['precision'])} | {fmt(s['empty_agree'])} | {fmt(s['cat_agree'])} | "
                   f"{s['drift']} | {s['parse_fail']} |")
    s = summarise(tot)
    ok = all([(s["cite_valid"] or 0) >= 0.95, (s["recall"] or 0) >= 0.80, (s["empty_agree"] or 0) >= 0.90])
    out.append(f"\n**Verdict:** {'ACCEPTABLE for the full run' if ok else 'NOT acceptable as-is'} "
               f"(thresholds: cite_valid ≥0.95, recall ≥0.80, empty_agree ≥0.90).\n")
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
