#!/usr/bin/env python3
"""Enumerate the defect classes the rules 1-10 re-verification pass was meant to close.

The re-verification was done record-by-record by readers, so each reader saw only its own
batch. That is exactly the shape of review that lets a systematic defect survive in the
records nobody looked at with the class in mind. This script asks the whole 50-record set
the same three questions mechanically, so "we fixed it" is an enumeration and not an
impression.

    python3 sweep_categories.py [--reference DIR]

Classes checked:
  A  rule 8  — a "must hold" gate (account, credential, privilege level, local access,
               prior compromise) filed under network-reachability instead of deployment.
  B  rule 9  — a "victim opens/executes/loads an artefact" gate filed under
               network-reachability instead of deployment.
  C  rule 10 — a record whose advisory_text names an optional component/service/feature
               that no precondition mentions. Heuristic and noisy by design: it reports
               candidates to read, not defects.
  D  hygiene — every precondition carries a `cites` that is a real substring of its own
               advisory_text (strict, then whitespace-normalised), and every record
               re-verified on this pass says so in `notes`.

Exit status is 1 if class A, B or D finds anything. Class C never fails the run.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent.parent))
from precondition_extraction.schema import normalise_text  # noqa: E402

# "must hold" — something the attacker possesses or has already achieved.
HOLD = re.compile(
    r"\b(authenticat|credential|password|account|logged[- ]in|log[- ]on|privileg|"
    r"administrat|admin\b|root\b|permission|local access|locally|physical access|"
    r"prior(ly)? compromis|already compromis|foothold|valid (user|login)|"
    r"api[- ]?(key|token)|session token|community string|shell access|"
    r"medium integrity|low integrity|integrity level)",
    re.I,
)
# "victim acts" — something the target's user or software must open or run.
VICTIM = re.compile(
    r"\b(victim|user must|user would|convince|entice|lure|persuade|trick|"
    r"opens?|open the|executes?|execute the|runs? the|clicks?|visit|loads? the|"
    r"downloads?|previews?)\b",
    re.I,
)
ARTEFACT = re.compile(
    r"\b(file|document|link|url|web ?site|web ?page|attachment|e-?mail|message|"
    r"image|archive|workbook|spreadsheet|\.lnk|html|pdf|application|package|"
    r"template|shortcut|payload)\b",
    re.I,
)
# Wording that genuinely is "the attacker must be able to reach X".
# Kept deliberately generous: a false negative here re-files a real reachability gate as a
# defect, which wastes a reader's time; the classes below are meant to be read, not obeyed.
# "send packets to" was added after the first run flagged CVE-2026-0300's genuine
# reachability gate, whose component NAME ("User-ID Authentication Portal") tripped HOLD.
REACH = re.compile(
    r"\b(reachab|accessible|exposed|internet[- ]facing|network access|"
    r"can reach|reach the|connect to|listening|outbound|egress|resolves?|"
    r"sends? (packets|requests?|traffic|data)|(packets|requests?|traffic) to|"
    r"over the network|remotely accessible|able to reach)\b",
    re.I,
)
# Optional-component wording in advisory prose. Deliberately broad.
COMPONENT = re.compile(
    r"\b(module|plug-?in|add-?in|add-?on|extension|service|daemon|agent|"
    r"feature|component|subsystem|portal|gateway|interface|connector|driver|"
    r"package|role|snap-?in|listener|endpoint)\b",
    re.I,
)
# A record must say which pass produced it. Two provenance markers are legitimate: the 50
# development records carry the re-verification line, the held-out records carry the blind
# build line. Anything with neither is a record whose origin nobody wrote down.
REVERIFIED = re.compile(r"Re-verified under rules 1[–-]10|Blind reference build", re.I)


def load(d: pathlib.Path) -> dict[str, dict]:
    out = {}
    for p in sorted(d.glob("CVE-*.yaml")):
        out[p.stem] = yaml.safe_load(p.read_text(encoding="utf-8"))
    return out


def blob(pc: dict) -> str:
    return f"{pc.get('id', '')} {pc.get('statement', '')}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reference", default=str(HERE / "reference"))
    a = ap.parse_args()
    recs = load(pathlib.Path(a.reference))
    if not recs:
        print("no records found", file=sys.stderr)
        return 2

    a_hits, b_hits, c_hits, d_hits, missing_note = [], [], [], [], []

    for cve, rec in sorted(recs.items()):
        text = rec.get("advisory_text") or ""
        ntext = normalise_text(text)
        exp = rec.get("expected") or {}
        pcs = exp.get("preconditions") or []

        if not REVERIFIED.search(str(exp.get("notes") or "")):
            missing_note.append(cve)

        for pc in pcs:
            cat, b = pc.get("category"), blob(pc)
            cites = pc.get("cites")

            # D — citation hygiene.
            if not cites:
                d_hits.append((cve, pc.get("id"), "no cites"))
            elif cites not in text:
                kind = "normalised only" if normalise_text(cites) in ntext else "NOT IN TEXT"
                d_hits.append((cve, pc.get("id"), kind))

            if cat != "network-reachability":
                continue
            # A — "must hold" wrongly under network-reachability.
            if HOLD.search(b) and not REACH.search(b):
                a_hits.append((cve, pc.get("id"), pc.get("statement", "")[:90]))
            # B — "victim opens artefact" wrongly under network-reachability.
            elif VICTIM.search(b) and ARTEFACT.search(b) and not REACH.search(b):
                b_hits.append((cve, pc.get("id"), pc.get("statement", "")[:90]))

        # C — advisory names a component, no precondition mentions it.
        named = {m.group(0).lower() for m in COMPONENT.finditer(text)}
        if named:
            covered = " ".join(blob(p) for p in pcs).lower()
            un = sorted(w for w in named if w not in covered)
            if un and pcs is not None:
                c_hits.append((cve, len(pcs), ", ".join(un[:6])))

    def show(title: str, rows, cols) -> None:
        print(f"\n=== {title} — {len(rows)} ===")
        for r in rows:
            print("  " + " | ".join(str(x) for x in r)) if cols else None

    show("A  rule 8: 'must hold' filed as network-reachability", a_hits, True)
    show("B  rule 9: 'victim opens artefact' filed as network-reachability", b_hits, True)
    show("D  citation hygiene", d_hits, True)
    print(f"\n=== C  advisory names a component no precondition mentions (READ, do not trust) — {len(c_hits)} ===")
    for r in c_hits:
        print(f"  {r[0]} | {r[1]} precondition(s) | unmatched: {r[2]}")
    print(f"\n=== records with no 're-verified' note — {len(missing_note)} ===")
    for c in missing_note:
        print("  " + c)

    hard = len(a_hits) + len(b_hits) + len(d_hits) + len(missing_note)
    print(f"\nrecords: {len(recs)}   hard failures (A+B+D+note): {hard}")
    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main())
