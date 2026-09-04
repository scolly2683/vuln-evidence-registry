#!/usr/bin/env python3
"""Inter-annotator agreement between two sets of precondition records.

    python3 agreement.py --a heldout/annotators/owner --b heldout/annotators/claude
    python3 agreement.py --a ... --b ... --disagreements   # the adjudication list

Why this exists. `compare.py` scores a candidate against a reference and calls one of
them right. That is the wrong frame for two annotators: neither is ground truth, and a
recall of 0.84 means nothing until you know what two careful readers score against each
other. If two experts only agree at 0.75, then a model at 0.84 is *above* the human
ceiling and "0.84" is a completely different claim.

The unit is the **sentence span**, not the precondition. Two annotators can name the same
gate differently ("captive-portal-service-present" vs "user-id-portal-running") and mean
exactly the same thing; what is comparable is *which sentence of the advisory each of them
read as carrying a gate*. So for every span of every shared record, each annotator either
cited it or did not — a 2x2 table, and Cohen's kappa over it.

Kappa rather than raw agreement because most spans carry no gate: on a 20-sentence advisory
with two gates, an annotator who marks nothing agrees with a careful one 90% of the time.
Kappa subtracts that chance agreement. Landis & Koch's conventional reading:
  < 0.00 poor · 0.00-0.20 slight · 0.21-0.40 fair · 0.41-0.60 moderate
  0.61-0.80 substantial · 0.81-1.00 almost perfect

Also reported, because kappa alone hides *where* the disagreement is:
  - span-level precision/recall of B against A (asymmetric view of the same table)
  - category agreement on spans both cited (do they read the same gate the same way?)
  - per-record counts, so one pathological advisory is visible rather than averaged away
"""
from __future__ import annotations

import argparse
import math
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE / "heldout"))
from precondition_extraction.schema import normalise_text  # noqa: E402


def load(d: pathlib.Path) -> dict[str, dict]:
    if not d.is_dir():
        raise SystemExit(f"error: no such directory: {d}")
    out = {}
    for p in sorted(d.glob("CVE-*.yaml")):
        out[p.stem] = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not out:
        raise SystemExit(f"error: {d} holds no CVE-*.yaml records")
    return out


def cited_spans(rec: dict, spans: list[str]) -> dict[int, str]:
    """span index -> category, for spans this annotator read as carrying a gate.

    A citation may cover part of a span or run across two; it counts for every span
    it overlaps under the shared normalisation, so an annotator is never punished for
    quoting a clause rather than the whole sentence.
    """
    out: dict[int, str] = {}
    nspans = [normalise_text(s) for s in spans]
    for pc in (rec.get("expected") or {}).get("preconditions") or []:
        c = normalise_text(pc.get("cites") or "")
        if not c:
            continue
        for i, ns in enumerate(nspans):
            if c and (c in ns or ns in c):
                out.setdefault(i, pc.get("category") or "?")
    return out


def kappa(both: int, a_only: int, b_only: int, neither: int) -> float | None:
    n = both + a_only + b_only + neither
    if not n:
        return None
    po = (both + neither) / n
    pa1, pb1 = (both + a_only) / n, (both + b_only) / n
    pe = pa1 * pb1 + (1 - pa1) * (1 - pb1)
    if math.isclose(pe, 1.0):
        return None  # no variance: both annotators marked everything, or nothing
    return (po - pe) / (1 - pe)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """Wilson 95% interval — the honest way to report a proportion at n=30."""
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="annotator A directory")
    ap.add_argument("--b", required=True, help="annotator B directory")
    ap.add_argument("--disagreements", action="store_true", help="print the adjudication list")
    args = ap.parse_args()

    from worksheet import spans  # the SAME splitter the owner annotated against

    A, B = load(pathlib.Path(args.a)), load(pathlib.Path(args.b))
    shared = sorted(set(A) & set(B))
    if not shared:
        raise SystemExit("error: the two annotators share no records")

    both = a_only = b_only = neither = 0
    cat_same = cat_diff = 0
    rows, disagreements = [], []

    for cve in shared:
        ra, rb = A[cve], B[cve]
        text = ra.get("advisory_text") or ""
        if normalise_text(text) != normalise_text(rb.get("advisory_text") or ""):
            print(f"WARNING {cve}: annotators hold different advisory_text — skipped", file=sys.stderr)
            continue
        ss = spans(text)
        ca, cb = cited_spans(ra, ss), cited_spans(rb, ss)
        rb_, ra_ = 0, 0
        for i in range(len(ss)):
            ina, inb = i in ca, i in cb
            if ina and inb:
                both += 1
                if ca[i] == cb[i]:
                    cat_same += 1
                else:
                    cat_diff += 1
                    if args.disagreements:
                        disagreements.append(
                            (cve, "CATEGORY", ss[i][:110], f"A={ca[i]}  B={cb[i]}"))
            elif ina:
                a_only += 1
                ra_ += 1
                if args.disagreements:
                    disagreements.append((cve, "A ONLY", ss[i][:110], _stmt(ra, ss[i])))
            elif inb:
                b_only += 1
                rb_ += 1
                if args.disagreements:
                    disagreements.append((cve, "B ONLY", ss[i][:110], _stmt(rb, ss[i])))
            else:
                neither += 1
        rows.append((cve, len(ss), len(ca), len(cb), ra_, rb_))

    n_spans = both + a_only + b_only + neither
    k = kappa(both, a_only, b_only, neither)
    # B-against-A, the asymmetric view: what compare.py would call recall/precision.
    rec = both / (both + a_only) if (both + a_only) else None
    pre = both / (both + b_only) if (both + b_only) else None

    print(f"# Agreement: A=`{args.a}`  B=`{args.b}`\n")
    print(f"{len(shared)} shared records, {n_spans} sentence spans\n")
    print("## Span-level contingency\n")
    print(f"  both cited      {both:5d}")
    print(f"  A only          {a_only:5d}")
    print(f"  B only          {b_only:5d}")
    print(f"  neither         {neither:5d}")
    print(f"\n  Cohen's kappa   {k:.3f}  ({_band(k)})" if k is not None else "\n  Cohen's kappa   n/a")
    if rec is not None:
        lo, hi = wilson(both, both + a_only)
        print(f"  B recall vs A   {rec:.2f}   95% CI [{lo:.2f}, {hi:.2f}]")
    if pre is not None:
        lo, hi = wilson(both, both + b_only)
        print(f"  B precision     {pre:.2f}   95% CI [{lo:.2f}, {hi:.2f}]")
    if both:
        print(f"  category agree  {cat_same / both:.2f}   ({cat_same}/{both} spans both cited)")

    print("\n## Per record\n")
    print("| CVE | spans | A gates | B gates | A only | B only |")
    print("|---|---|---|---|---|---|")
    for r in rows:
        print("| " + " | ".join(str(x) for x in r) + " |")

    if args.disagreements and disagreements:
        print(f"\n## Adjudication list — {len(disagreements)}\n")
        for cve, kind, span, detail in disagreements:
            print(f"### {cve}  [{kind}]")
            print(f"    span:   {span}")
            print(f"    detail: {detail}\n")
    elif args.disagreements:
        print("\n## Adjudication list — 0")
        print("Zero disagreements across every span is not a result, it is a bug:")
        print("check the two directories are genuinely different annotators.")
    return 0


def _stmt(rec: dict, span: str) -> str:
    ns = normalise_text(span)
    for pc in (rec.get("expected") or {}).get("preconditions") or []:
        c = normalise_text(pc.get("cites") or "")
        if c and (c in ns or ns in c):
            return f"[{pc.get('category')}] {pc.get('statement', '')[:110]}"
    return "(no matching gate)"


def _band(k: float) -> str:
    for edge, name in ((0.0, "poor"), (0.20, "slight"), (0.40, "fair"),
                       (0.60, "moderate"), (0.80, "substantial")):
        if k <= edge:
            return name
    return "almost perfect"


if __name__ == "__main__":
    raise SystemExit(main())
