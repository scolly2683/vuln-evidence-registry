# Setting up the Copilot notebook

## Sources to add — and what to leave out

**Add these five, in this order — order matters, the first one outranks the rest:**

| # | Source | Why |
|---|---|---|
| 1 | **Your existing environment prompt file** (schemas, reports, existing routing queues, what's already built) | This is the authority on your estate. Everything else defers to it. |
| 2 | `6-notebook-source.md` | The routing model, channel semantics and response conventions. Its precedence block explicitly defers to source 1 on environment facts. |
| 3 | `1-routing-query-readonly.sql` | The actual query, so Copilot edits *your* SQL rather than inventing it. |
| 4 | `3-powerbi-build.md` | Measures and visual choices. |
| 5 | `8-log4j-triage-playbook.md` | Only if you're working a detection storm. Otherwise leave it out until needed. |

**Before you rely on the notebook, do the reconciliation** in section 4a of
`6-notebook-source.md`: map the 18 proposed channels onto the routing queues
you already have, keeping your existing names. Then edit section 4 of that
file to the reconciled list and re-upload it. Skipping this is the most
likely way to end up with two competing sets of queue names.

A useful first prompt once both sources are loaded:

> Compare the routing queues described in my environment file with the fix
> channels in section 4 of the routing reference. Produce a three-column
> table: existing queue, matching channel (or "none"), and channels with no
> existing equivalent. Do not suggest renaming my existing queues.

**Do not add** the wider document set from the repo. Several files contradict
each other on purpose and will produce confident wrong answers:

- `sql-powerbi.md` — written in **SQL Server** syntax. If Copilot reads it you
  will get `CHARINDEX`/`ISNULL` that fails on Oracle.
- `estate-blueprint.md`, `industry-research.md`, `architecture-review.md` —
  these argue options and describe things that are *not built*. Copilot will
  present designs as if they exist.
- `4-full-ddl-if-write-access.sql` — creates tables you cannot create.

If a notebook starts giving odd answers, the cause is almost always an extra
source. Remove sources before rewriting prompts.

## Prompt starters to save in the notebook

Grounded questions work better than open ones. Save these:

- *Rewrite the `f` CTE in the routing query to use my column names from the
  DESCRIBE note. Use CAST(NULL AS …) where I have no equivalent column.*
- *List the unrouted work queue: group unrouted findings by vendor and
  product, count findings, distinct CVEs and distinct assets, top 25.*
- *Write one DAX measure for [X] against the report columns. Include the
  format string and one sentence of explanation.*
- *I want to answer "[question]" on a page. Recommend one visual, the exact
  field wells, the sort, and one formatting setting.*
- *Turn these products into rule lines in the `rl` CTE format. Ask me which
  channel where it is ambiguous instead of guessing.*
- *Explain why this query returns more rows than my findings table and how
  the ROW_NUMBER partition prevents it.*

## When answers are too long and under-thought

Long *and* shallow is one symptom with one usual cause: **the question was
too broad, so it padded.** Narrowing the ask fixes both at once. Section 0 of
the reference sets the default; these are the per-prompt levers.

**Suffixes that work** (paste at the end of any prompt):

- `Answer in at most 5 lines. Code first, no preamble.`
- `Return only the SQL. No explanation.`
- `Pick one approach. One sentence why. Do not list alternatives.`
- `If anything is ambiguous, ask me one question instead of assuming.`

**Force the shape** — the strongest lever. Give it a template to fill:

> Reply using exactly this template, nothing else:
> **Measure:** `<name>`
> **DAX:** ```<code>```
> **Format:** `<format string>`
> **Why:** one sentence

**Cut the scope, not just the length.** "Build the ageing page" invites an
essay; "one visual for overdue findings by owner team — field wells and sort
only" gets a usable answer. One measure, one visual, one CTE per ask.

**Fix depth, not verbosity, when it's wrong rather than waffly:**

- `Which section of the reference did you use? Quote the line.` — surfaces
  invented grounding straight away.
- `What would make this answer wrong?` — one follow-up, catches most of it.
- `Revise the previous answer only where it's wrong. Do not restate it.` —
  stops the full-length regeneration.

**If extended thinking makes it worse,** turn it off for these tasks. Writing
one measure or one CTE against a known schema is a lookup, not a reasoning
problem — the extra deliberation mostly produces more prose. Keep it on only
for "why is my query returning duplicate rows" style diagnosis.

## Keeping it accurate

- When the channel owners or SLAs change, **edit section 4 of
  `6-notebook-source.md` and re-upload it**. Do not correct Copilot in chat —
  that fix lasts one conversation.
- When rules are added to the query, re-upload the query file monthly or so.
  Copilot does not need every rule, but it should not be reading a version
  that predates a channel you added.
- One source of truth: if you write new material, either fold it into
  `6-notebook-source.md` or explicitly mark it "reference only, superseded by
  the authoritative reference".

## What a notebook is good at here

- Explaining the system to a colleague ("summarise how routing decides an
  owner") — it has the whole model in one place.
- Writing a measure or a query against the real schema.
- Turning a list of unrouted products into rule lines.

## What it will still get wrong

- **Visual layout choices.** It suggests too many visuals and reaches for pie
  charts. Section 7 of the reference constrains this, but check its answers.
- **Anything about volumes or scale in your estate** — it has no data, only
  the schema.
- **Oracle syntax drift** on long answers. Section 2 tells it the rule; if a
  reply contains `CHARINDEX` or `ISNULL`, reject and re-ask rather than
  hand-fixing, because the rest of that answer is likely SQL-Server-shaped
  too.
