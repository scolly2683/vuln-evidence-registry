# NIST NVD RFI — public comment (docket NIST-2026-0100)

**Status: drafted, NOT filed.** Deadline **13 October 2026**, at
[regulations.gov](https://www.regulations.gov) under docket NIST-2026-0100.

| file | what it is |
|---|---|
| `NIST-2026-0100-comment.md` | **The source of truth.** Edit this. |
| `NIST-2026-0100-comment.docx` | Generated from the markdown, for reading and filing. |
| `make_docx.js` | Regenerates the .docx. Run it after any edit to the markdown. |

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
