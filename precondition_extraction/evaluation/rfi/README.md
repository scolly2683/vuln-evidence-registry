# NIST NVD RFI — public comment (docket NIST-2026-0100)

**Status: drafted, NOT filed.** Deadline **13 October 2026**, at
[regulations.gov](https://www.regulations.gov) under docket NIST-2026-0100.

| file | what it is |
|---|---|
| `NIST-2026-0100-comment-short.md` | **The comment.** Source of truth — edit this. ~1,050 words. |
| `NIST-2026-0100-comment-short.docx` | Generated from the markdown, for reading and filing. |
| `make_docx.js` | Regenerates the .docx: `node make_docx.js <in.md> <out.docx>`. Run after any edit. |

The .docx is derived. If the two ever disagree, the markdown is right — regenerate rather
than editing the Word file, or the next regeneration silently discards the edit.

## Deliberate omissions

**The comment does not link to this repository.** By the author's decision (2026-09-04) it
says "I measured" and gives the figures, and stops there. The benchmark section that
offered the reference sets to NIST was removed with it. If a reader asks for the data, the
pinned tree is commit `7f1da34` on `main`, which holds every figure quoted — it can be
supplied on request. The trade-off is stated plainly: without the link, nothing in the
comment can be independently verified by a reader; with it, the author's project becomes
part of the public record. A longer earlier draft that included both is in git history
(`git log -- precondition_extraction/evaluation/rfi/NIST-2026-0100-comment.md`).

## What the comment argues

Three claims, one RFI topic area (data and standards), all resting on 170 exploited edge
CVEs and the 1,687-record CISA KEV catalogue — not on the 50-record development set,
which no longer appears:

1. **The `configurations` field's presence is measurable and nobody had measured it.** Same
   assigning organisation: 8 records with the field filled yielded 2.88 conditions each and
   none yielded nothing; 3 without it yielded 0.00 and all three yielded nothing.
2. **"No special configuration is required" is an answer, not padding** — operationally
   the opposite of silence — so the minimum useful structure is a three-way distinction
   (no condition / condition / not assessed), not a rich taxonomy.
3. **Nobody ever told CNAs the field exists** — the CNA Operational Rules mention it zero
   times.

## Before filing

One placeholder remains: `[NAME]`. Everything else is done. Open the .docx once to check
it on screen; comments are posted in full, without redaction.
