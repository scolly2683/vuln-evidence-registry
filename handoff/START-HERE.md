# CVE routing — everything you need, in order

Four files. You need **read-only** database access and Power BI. No Python,
no admin rights, nothing to install.

---

## What this adds to your report

Your findings report today: CVE, asset, severity, age.
What it's missing: **who fixes this** and **by when**.

These files add five columns:

| Column | Example |
|---|---|
| `ROUTING_STATUS` | `ROUTED` / `UNROUTED` |
| `CHANNEL_NAME` | On-prem Windows servers |
| `OWNER_GROUP` | Windows server team |
| `DUE_DATE` | first seen + SLA (DMZ assets get 7 days) |
| `OVERDUE_FLAG` | `Y` / `N` |

`UNROUTED` is the analyst queue — findings no rule knows yet. Every one an
analyst adjudicates becomes a rule, so the queue shrinks month over month.
That percentage falling is the metric that proves it's working.

---

## Do these in order

### 1 — `1-routing-query-readonly.sql` (15 minutes)

Open it and edit the **PLACEHOLDERS** block at the top: your findings table
name and column names. If a column doesn't exist (e.g. no `PURL`), replace it
with `NULL`. Nothing breaks.

Then in Power BI:
> Get Data → Oracle database → your server/service → **Advanced options** →
> paste the whole query into **SQL statement** → Import

Check the preview has the new columns. That's the hard part done.

**Tip:** add your own filter inside the `f` block (e.g.
`WHERE STATUS='OPEN'`) so Oracle does the filtering, not Power BI.

### 2 — `3-powerbi-build.md` (an afternoon)

Model setup, the DAX measures to paste, and four report pages with the exact
visual to use for each — plus what to avoid (no pie charts with 18 channels).
There's also a schema block to paste into Copilot so its DAX suggestions are
accurate.

Build **page 3 first** — the analyst queue table. It's the one that creates
work you can act on immediately.

### 3 — `2-analyst-triage-tool.html` (give to analysts)

Double-click to open in any browser. Nothing installs, nothing is uploaded.

Analyst workflow:
1. Export the unrouted rows from the Power BI queue page (or paste a CVE list)
2. Paste into the tool → hit **Route findings**
3. Green rows have an owner. **Amber rows are the work.**
4. For an amber group, click **add rule** → type the technology, pick the
   channel → everything re-routes instantly
5. Click **Copy query rows** and send you the lines

Click **Load example** first to see it working in ten seconds.

### 4 — Weekly, 10 minutes (you)

Paste the analysts' lines into the query, above the marker:

```
  -- >>> ADD ANALYST RULES BELOW THIS LINE <<<
```

Refresh the dataset. The queue is smaller. That's the whole loop.

---

## The one rule for analysts

**Decide once, in the tool — not in the scanner console.**

A decision made in Qualys/Wiz helps one scan. A decision made in the tool
becomes a rule that routes every future CVE for that technology, with your
name and reason attached to it.

---

## Also in the bundle

- `4-full-ddl-if-write-access.sql` — the same thing as real tables and a view,
  for if you ever get write access. Ignore it for now.
- `5-copilot-prompts.md` — prompts for a normal Copilot chat session.
- `6-notebook-source.md` + `7-notebook-setup.md` — for a Copilot **notebook**.
  Read the precedence block at the top of file 6 first: **your existing
  environment prompt file wins** on schema, reports and existing routing
  queues. File 6 only adds the routing model.
- `8-log4j-triage-playbook.md` — how to take a 500-detection storm down to the
  handful that are real, and how to reuse that for the next one.

## Fitting this to what already exists

**Do this before building anything.** Take your current routing queues and
map them onto the 18 channels (section 4a of file 6). Keep your existing
queue names — rename the channel, not the queue — so saved reports and team
habits keep working. What's left over are the genuinely new splits (endpoint
vs server Windows, macOS vs iOS, base image vs app dependency).

This model is meant to change *how findings get assigned*, not *what your
queues are called*.

## Things to know

- The channel list (18) and owners in the files are **assumptions** — edit
  them to your real teams. That's a one-hour workshop, and it's the highest-
  value thing you can change.
- Keyword matching is deliberately simple (substring on product/description).
  It will occasionally misroute — that's what the analyst queue and rule
  priorities are for. Lower priority number wins.
- SLAs default to 30 days (7 for DMZ, 5 for Windows endpoints, 90 for Oracle
  CPU). Change them in the `ch` block.
