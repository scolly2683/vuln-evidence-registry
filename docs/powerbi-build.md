# Power BI: what to build on VM_FINDING_ROUTED

Point the dataset at the one Oracle view (`sql/oracle/routing_oracle.sql`).
Import mode, scheduled refresh — routing changes at batch cadence.

## M / model setup (30 seconds of it)

- Source: Oracle → `VM_FINDING_ROUTED`. Take the whole view; don't filter in M.
- Set types: `FIRST_SEEN`, `DUE_DATE` → **Date**; `SLA_DAYS`, `AGE_DAYS` → whole number.
- Add a Date table, mark it as a date table, relate it to `FIRST_SEEN`
  (single direction, one-to-many). Without this, no trend visual behaves.
- Nothing else. Resist adding calculated columns — the view already carries
  status, owner, due date and overdue flag.

## Measures (paste these)

```dax
Findings      = COUNTROWS ( VM_FINDING_ROUTED )

Unrouted      = CALCULATE ( [Findings], VM_FINDING_ROUTED[ROUTING_STATUS] = "UNROUTED" )
Unrouted %    = DIVIDE ( [Unrouted], [Findings] )

Routed        = CALCULATE ( [Findings], VM_FINDING_ROUTED[ROUTING_STATUS] = "ROUTED" )
Suppressed    = CALCULATE ( [Findings], VM_FINDING_ROUTED[ROUTING_STATUS] = "SUPPRESSED" )

Overdue       = CALCULATE ( [Findings], VM_FINDING_ROUTED[OVERDUE_FLAG] = "Y" )
Overdue %     = DIVIDE ( [Overdue], [Routed] )

Avg age days  = AVERAGE ( VM_FINDING_ROUTED[AGE_DAYS] )
Assets        = DISTINCTCOUNT ( VM_FINDING_ROUTED[ASSET_ID] )
CVEs          = DISTINCTCOUNT ( VM_FINDING_ROUTED[CVE_ID] )

-- headline: how much of routing is knowledge we added, not seed defaults
Queue trend   = CALCULATE ( [Unrouted %], DATEADD ( 'Date'[Date], -1, MONTH ) )
```

Format `Unrouted %` and `Overdue %` as percentage, 1 decimal. Format
`Findings`/`Overdue` as whole number with thousands separator.

## Visuals — what to use, and what to avoid

You said visuals are the struggle. The fix is fewer, better-chosen ones.
Four pages, each answering one question.

### Page 1 — Are we on top of it?
| Visual | Field wells | Why this one |
|---|---|---|
| **Card** ×3 | `Findings`, `Overdue`, `Unrouted %` | Three numbers, nothing else. Big. |
| **Line chart** | Axis `Date[Month]`, Values `Unrouted %` | The convergence curve. The only trend that proves the system is learning. |
| **Clustered bar** (not column) | Axis `CHANNEL_NAME`, Values `Findings` | Horizontal — channel names are long and won't be readable rotated. Sort descending by value. |

### Page 2 — Who owns the work?
| Visual | Field wells | Notes |
|---|---|---|
| **Matrix** | Rows `OWNER_GROUP` → `CHANNEL_NAME`, Values `Findings`, `Overdue`, `Overdue %` | Matrix, not table — the drill-down replaces five separate visuals. |
| **Stacked bar** | Axis `OWNER_GROUP`, Legend `SEVERITY`, Values `Findings` | 100% stacked only if you care about mix, not volume. |

Apply **conditional formatting → background colour** on the `Overdue` column
(white → amber). That one setting does more than any chart on this page.

### Page 3 — The analyst queue
| Visual | Field wells |
|---|---|
| **Table** | `VENDOR`, `PRODUCT`, `CVEs`, `Assets`, `Findings` — filtered to `ROUTING_STATUS = "UNROUTED"`, sorted by `Findings` desc |
| **Slicers** | `SOURCE` (Qualys/Wiz/GitHub), `ZONE`, `SEVERITY` |

This page *is* the work: top row = biggest group = next decision. Export it,
paste into the triage tool, add rules.

### Page 4 — Suppression ledger
Table of `ROUTING_STATUS = "SUPPRESSED"` with `SUPPRESSION_VERDICT`, plus a
card counting suppressions expiring in 30 days (drive from `VM_SUPPRESSION`
as a second query). Governance evidence in one page.

### Avoid
- **Pie/donut** — you have 18 channels; nobody can read it. Bar chart.
- **Multi-row cards** for KPIs — use separate Cards; they read at a glance.
- **Tables with 15 columns** — that's what the matrix drill-down is for.
- **Dual-axis combo charts** for count + percentage — split into two visuals.
- Gauges. Always.

## Prompting Copilot against this

Copilot does better with the schema pinned. Paste this preamble:

> Table `VM_FINDING_ROUTED` in Oracle. Columns: FINDING_ID, CVE_ID, ASSET_ID,
> VENDOR, PRODUCT, SEVERITY, SOURCE, ZONE, FIRST_SEEN (date),
> ROUTING_STATUS ('ROUTED'|'UNROUTED'|'SUPPRESSED'), CHANNEL_ID, CHANNEL_NAME,
> OWNER_GROUP, DECIDED_BY_RULE, SLA_DAYS, DUE_DATE (date), AGE_DAYS,
> OVERDUE_FLAG ('Y'|'N'). Write DAX for … / Write an Oracle query that …

Ask it for **one measure at a time**. Copilot is reliable at single measures
and unreliable at "build me a report" — the visual choices above are the part
it gets wrong most often.
