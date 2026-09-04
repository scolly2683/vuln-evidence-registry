# NIST NVD RFI — public comment (docket NIST-2026-0100)

**Status: drafted, NOT filed.** Deadline **13 October 2026**, at
[regulations.gov](https://www.regulations.gov) under docket NIST-2026-0100.

| file | what it is |
|---|---|
| `NIST-2026-0100-comment-short.md` | **Recommended for filing** — ~1,100 words, ask up front, same figures. |
| `NIST-2026-0100-comment.md` | The long version (~1,950 words). Kept for comparison; same claims, more hedging and more method. |
| `*.docx` | Generated from the matching markdown, for reading and filing. |
| `make_docx.js` | Regenerates a .docx: `node make_docx.js <in.md> <out.docx>`. Run after any edit. |

Both versions carry identical figures, checked mechanically. The short one names Konvu
directly instead of "another comment", states the three asks in the opening section, puts
the n=3 caveat at the point of use, and cuts the benchmark section to one paragraph — a
NIST reader is not the audience for the method.

```bash
npm install docx          # once
node make_docx.js NIST-2026-0100-comment.md NIST-2026-0100-comment.docx
```

The .docx is a **derived file**. If the two ever disagree, the markdown is right and the
.docx is stale — regenerate rather than editing the Word file, or the next regeneration
silently discards the edit.

## Before filing

Two placeholders remain (`[NAME]`, and the self-description), and the checklist at the end
of the comment covers the rest. The repository citation is already pinned to commit
`7f1da34`, which is on `main` and contains every figure quoted.

## What the comment argues

Three claims, one RFI topic area (data and standards):

1. **The `configurations` field's presence is measurable and nobody had measured it.** Same
   assigning organisation: 8 records with the field filled yielded 2.88 conditions each and
   none yielded nothing; 3 records without it yielded 0.00 and all three yielded nothing.
2. **"No special configuration is required" is an answer, not padding** — it is
   operationally the opposite of silence, and the minimum useful structure is a three-way
   distinction (no condition / condition / not assessed) rather than a rich taxonomy.
3. **A public benchmark of the kind already requested on this docket exists** and is offered.

Evidence, method and limits: `../COVERAGE.md` and `../README.md` (*Seventh pass*).
