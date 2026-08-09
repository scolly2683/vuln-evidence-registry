# Routing registry → SQL & Power BI

How to run the registry's rules inside an in-house SQL database that feeds
Power BI — **without creating a second hand-maintained implementation that
drifts from the YAML engine.**

## 1. The drift problem

Pattern 1 of this repo (`vuln_evidence_registry/evidence_sources.py`) exists
because of one recurring failure: the same decision hand-wired twice — once
as SQL over the corpus, once as a per-record predicate — silently diverging.
The routing registry has exactly the same exposure, and the same fix:

> **One source of truth, two composed outputs.** YAML in git stays canonical
> (review, provenance, `git blame`, regression fixtures). The database gets
> rule tables **generated** from that YAML — never hand-edited — plus one
> generic routing view that interprets them. Rules change in git only; the
> DB reloads.

**Anti-goal:** encoding rules as hand-written `CASE WHEN vendor = 'oracle'…`
SQL. Every new correction would then be a schema-change ticket, the audit
trail would split in two, and drift is guaranteed. Rules are *data*; the SQL
below treats them as data.

## 2. Architecture: five hops, one direction

```
YAML in git ──▶ export step ──▶ rule tables ──▶ routing views ──▶ Power BI
(canonical)     (CI on merge)    (reg.*,          (generic,        (trend,
                                  reload only)     first-match)     queues)
```

Data flows one way. Nothing in the DB or Power BI writes rules back — a
misroute spotted in a report becomes a `propose-correction` in git, which
flows forward again on the next reload.

The export step is `tools/export_registry_sql.py` (in this repo, tested):

```bash
python tools/export_registry_sql.py --registry registry \
    --fixtures fixtures/regression.yaml --out export
```

It validates the registry first, refuses to export any construct the SQL
view can't faithfully evaluate, and writes six CSVs: `channels.csv`,
`rules.csv`, `rule_predicates.csv`, `fixtures.csv`, `fixture_findings.csv`,
`fixture_finding_context.csv`.

## 3. Rule tables

T-SQL shown (SQL Server is the usual Power BI back end); dialect notes in
§9. The key design move: **one row per predicate value** in
`reg.rule_predicates`, which is what lets one generic view interpret every
rule.

```sql
CREATE SCHEMA reg;

CREATE TABLE reg.channels (
    channel_id    varchar(40)   NOT NULL PRIMARY KEY,  -- 'oracle-cpu'
    channel_name  nvarchar(100) NOT NULL,
    cadence       nvarchar(200) NULL,
    cadence_type  varchar(20)   NOT NULL,              -- scheduled | continuous | ad_hoc
    owner_group   nvarchar(100) NULL
);

CREATE TABLE reg.rules (
    rule_id          varchar(80)  NOT NULL PRIMARY KEY,
    kind             varchar(12)  NOT NULL,             -- screen | correction | identity
    priority         int          NOT NULL DEFAULT 100, -- lower wins within a stage
    route_channel_id varchar(40)  NULL
        REFERENCES reg.channels (channel_id),           -- NULL for screens
    screen_action    varchar(8)   NULL,                 -- drop | park   (screens only)
    park_queue       varchar(60)  NULL,
    review_by        date         NULL,                 -- volatile-fact re-check date
    decided_by       nvarchar(60) NULL,                 -- provenance (corrections)
    decided_on       date         NULL,
    trigger_note     nvarchar(1000) NULL
);

CREATE TABLE reg.rule_predicates (
    rule_id    varchar(80)   NOT NULL REFERENCES reg.rules (rule_id),
    pred_type  varchar(20)   NOT NULL,  -- cna | vendor | product | package | source
                                        --   | nvd_status | keywords | purl_prefix | context
    pred_key   varchar(40)   NOT NULL DEFAULT '',  -- context key when pred_type='context'
    pred_value nvarchar(200) NOT NULL
);
CREATE INDEX ix_rule_predicates ON reg.rule_predicates (rule_id, pred_type, pred_key);
```

Findings staging — however your pipeline lands them today:

```sql
CREATE SCHEMA vm;

CREATE TABLE vm.findings (
    finding_id  varchar(60)    NOT NULL PRIMARY KEY,
    run_date    date           NOT NULL,          -- batch date: the Power BI trend axis
    cve_id      varchar(20)    NULL,
    cna         nvarchar(100)  NULL,
    vendor      nvarchar(200)  NULL,
    product     nvarchar(300)  NULL,
    package     nvarchar(200)  NULL,
    purl        nvarchar(300)  NULL,
    description nvarchar(2000) NULL,
    nvd_status  varchar(30)    NULL,
    source      varchar(30)    NULL               -- 'qualys' | 'wiz' | 'github' | …
);

-- Deployment context: one row per (finding, key). Absence of a row = fact
-- unknown, which is load-bearing — see §4.
CREATE TABLE vm.finding_context (
    finding_id    varchar(60)   NOT NULL REFERENCES vm.findings (finding_id),
    context_key   varchar(40)   NOT NULL,   -- 'bundle_member', 'image_layer', …
    context_value nvarchar(100) NOT NULL,   -- 'false', 'base', 'app', …
    PRIMARY KEY (finding_id, context_key)
);
```

## 4. Matching semantics, translated exactly

The SQL must reproduce `router.py` semantics precisely, or the parity gate
in §6 will (correctly) fail.

| Predicate | Engine semantics | SQL translation |
|---|---|---|
| `vendor`, `cna`, `product`, `package`, `source` | Field non-empty; matches if any allowed value equals *or is contained in* the field ("red hat" matches "Red Hat, Inc."). Case-insensitive. | `LOWER(field) = LOWER(v) OR CHARINDEX(LOWER(v), LOWER(field)) > 0`, guarded by non-empty |
| `nvd_status` | Same equality-or-contained rule | Same as above |
| `keywords` | Case-insensitive substring over **product + package + description concatenated**; any keyword suffices | `CHARINDEX(LOWER(kw), LOWER(CONCAT(product,' ',package,' ',description))) > 0` |
| `purl_prefix` | purl present and starts with any listed prefix | `LOWER(purl) LIKE LOWER(prefix) + '%'`, guarded by non-empty |
| `context` | **Key must be present** AND value must match; absent key = predicate fails (corrections safe by default) | `EXISTS` against `vm.finding_context` — a missing row naturally fails |
| within one rule | Same predicate type = **OR**; different types = **AND** | Relational division — the double `NOT EXISTS` in §5 |
| across rules | Stage order **screen → correction → identity**; within a stage `(priority, rule_id)`; first full match wins | `ROW_NUMBER() OVER (PARTITION BY finding ORDER BY stage_rank, priority, rule_id) = 1` |
| no match | `unroutable` — the adjudication queue | `LEFT JOIN` from findings; NULL rule → `'unroutable'` |

## 5. The routing views — the whole engine in two views

```sql
CREATE VIEW vm.vw_rule_matches AS
SELECT
    f.finding_id,
    r.rule_id, r.kind, r.priority, r.route_channel_id, r.screen_action, r.park_queue
FROM vm.findings f
CROSS JOIN reg.rules r
WHERE NOT EXISTS (               -- no predicate group of this rule fails…
    SELECT 1
    FROM (
        SELECT DISTINCT rule_id, pred_type, pred_key
        FROM reg.rule_predicates
    ) g
    WHERE g.rule_id = r.rule_id
      AND NOT EXISTS (           -- …a group fails when none of its values match
          SELECT 1
          FROM reg.rule_predicates p
          WHERE p.rule_id  = g.rule_id
            AND p.pred_type = g.pred_type
            AND p.pred_key  = g.pred_key
            AND (
                 (p.pred_type = 'vendor'
                    AND f.vendor IS NOT NULL AND f.vendor <> ''
                    AND (LOWER(f.vendor) = LOWER(p.pred_value)
                         OR CHARINDEX(LOWER(p.pred_value), LOWER(f.vendor)) > 0))
              OR (p.pred_type = 'cna'
                    AND f.cna IS NOT NULL AND f.cna <> ''
                    AND (LOWER(f.cna) = LOWER(p.pred_value)
                         OR CHARINDEX(LOWER(p.pred_value), LOWER(f.cna)) > 0))
              OR (p.pred_type = 'product'
                    AND f.product IS NOT NULL AND f.product <> ''
                    AND (LOWER(f.product) = LOWER(p.pred_value)
                         OR CHARINDEX(LOWER(p.pred_value), LOWER(f.product)) > 0))
              OR (p.pred_type = 'package'
                    AND f.package IS NOT NULL AND f.package <> ''
                    AND (LOWER(f.package) = LOWER(p.pred_value)
                         OR CHARINDEX(LOWER(p.pred_value), LOWER(f.package)) > 0))
              OR (p.pred_type = 'source'
                    AND f.source IS NOT NULL AND f.source <> ''
                    AND (LOWER(f.source) = LOWER(p.pred_value)
                         OR CHARINDEX(LOWER(p.pred_value), LOWER(f.source)) > 0))
              OR (p.pred_type = 'nvd_status'
                    AND f.nvd_status IS NOT NULL AND f.nvd_status <> ''
                    AND (LOWER(f.nvd_status) = LOWER(p.pred_value)
                         OR CHARINDEX(LOWER(p.pred_value), LOWER(f.nvd_status)) > 0))
              OR (p.pred_type = 'keywords'
                    AND CHARINDEX(
                          LOWER(p.pred_value),
                          LOWER(CONCAT(ISNULL(f.product, ''), ' ',
                                       ISNULL(f.package, ''), ' ',
                                       ISNULL(f.description, '')))) > 0)
              OR (p.pred_type = 'purl_prefix'
                    AND f.purl IS NOT NULL AND f.purl <> ''
                    AND LOWER(f.purl) LIKE LOWER(p.pred_value) + '%')
              OR (p.pred_type = 'context'
                    AND EXISTS (
                        SELECT 1
                        FROM vm.finding_context c
                        WHERE c.finding_id  = f.finding_id
                          AND c.context_key = p.pred_key
                          AND LOWER(c.context_value) = LOWER(p.pred_value)))
            )
      )
);
```

```sql
CREATE VIEW vm.vw_routing AS
WITH ranked AS (
    SELECT
        m.*,
        ROW_NUMBER() OVER (
            PARTITION BY m.finding_id
            ORDER BY CASE m.kind          -- stage order is the pipeline
                         WHEN 'screen'     THEN 1
                         WHEN 'correction' THEN 2
                         WHEN 'identity'   THEN 3
                     END,
                     m.priority,
                     m.rule_id            -- deterministic tie-break, same as the engine
        ) AS rn
    FROM vm.vw_rule_matches m
)
SELECT
    f.finding_id, f.cve_id, f.run_date,
    CASE
        WHEN r.rule_id IS NULL  THEN 'unroutable'
        WHEN r.kind = 'screen'  THEN 'screened'
        ELSE 'routed'
    END AS disposition,
    CASE WHEN r.kind IN ('correction', 'identity')
         THEN r.route_channel_id END AS channel_id,
    r.rule_id,
    r.kind AS stage,
    CASE WHEN r.kind = 'screen' AND r.screen_action = 'park'
         THEN r.park_queue END AS park_queue
FROM vm.findings f
LEFT JOIN ranked r
       ON r.finding_id = f.finding_id AND r.rn = 1;
```

**That's the entire engine.** Adding a correction in git adds rows to two
tables on the next reload — no view changes, no deploy, no BI rework.

**Performance:** the `CROSS JOIN` is rules × findings — trivial at seed
scale (~30 rules × ~10k monthly cohort). If it ever isn't, materialize the
view into a routing-results table per batch; Power BI prefers that shape
anyway.

## 6. The parity gate — SQL's version of the regression fixtures

The Python engine is guarded by regression fixtures in CI. The SQL twin gets
the **same fixtures, as a query that must return zero rows.** The exporter
emits the fixture findings and context, so this gate is runnable end to end.

```sql
CREATE TABLE reg.fixtures (               -- from fixtures.csv
    fixture_name          varchar(80) NOT NULL PRIMARY KEY,
    finding_id            varchar(60) NOT NULL,
    expected_disposition  varchar(12) NOT NULL,  -- routed | screened | unroutable
    expected_channel_id   varchar(40) NULL,
    expected_rule_id      varchar(80) NULL
);

-- The gate. Run after every rule reload. Zero rows = the SQL twin agrees
-- with every decision the analysts ever made. Any row = drift; block the load.
SELECT
    x.fixture_name,
    x.expected_disposition, v.disposition,
    x.expected_channel_id,  v.channel_id,
    x.expected_rule_id,     v.rule_id
FROM reg.fixtures x
JOIN vm.vw_routing v ON v.finding_id = x.finding_id
WHERE v.disposition <> x.expected_disposition
   OR ISNULL(v.channel_id, '') <> ISNULL(x.expected_channel_id, '')
   OR ISNULL(v.rule_id, '')    <> ISNULL(x.expected_rule_id, '');
```

**Treat a non-empty result as a build failure, not a curiosity.** Reload
rules → run the gate → commit the load only on zero rows. This single query
is what earns the right to say the dashboard and the engine give the same
answers.

## 7. The Power BI layer

Point the dataset at views, not raw tables. Import mode with scheduled
refresh is fine — routing changes at batch cadence, not real time.

```sql
-- One row per finding per batch: everything the report needs
CREATE VIEW vm.vw_pbi_routing AS
SELECT r.finding_id, r.cve_id, r.run_date, r.disposition, r.stage,
       r.rule_id, r.park_queue,
       c.channel_id, c.channel_name, c.cadence_type, c.owner_group
FROM vm.vw_routing r
LEFT JOIN reg.channels c ON c.channel_id = r.channel_id;

-- The analyst work queue, ready for a report page
CREATE VIEW vm.vw_pbi_unroutable AS
SELECT f.finding_id, f.cve_id, f.run_date, f.vendor, f.product, f.description
FROM vm.vw_routing r
JOIN vm.findings f ON f.finding_id = r.finding_id
WHERE r.disposition = 'unroutable';

-- Hygiene debt: rules whose volatile facts are due for re-verification
CREATE VIEW vm.vw_pbi_review_due AS
SELECT rule_id, kind, route_channel_id, review_by, decided_by, trigger_note
FROM reg.rules
WHERE review_by IS NOT NULL AND review_by <= CAST(GETDATE() AS date);
```

DAX measures:

```
Findings          = COUNTROWS ( Routing )
Unroutable        = CALCULATE ( [Findings], Routing[disposition] = "unroutable" )
Unroutable %      = DIVIDE ( [Unroutable], [Findings] )
   -- THE metric. Chart by run_date from run one: falling = learning.
Routed            = CALCULATE ( [Findings], Routing[disposition] = "routed" )
Screened %        = DIVIDE ( CALCULATE ( [Findings],
                        Routing[disposition] = "screened" ), [Findings] )
Correction share  = DIVIDE ( CALCULATE ( [Routed],
                        Routing[stage] = "correction" ), [Routed] )
   -- How much of routing is learned knowledge vs. seed identity rules.
Rules past review = COUNTROWS ( ReviewDue )
```

The four report pages worth building:

1. **Convergence** *(the headline)* — Unroutable % by run_date as a line,
   findings volume as context. The one chart that justifies the system.
2. **Channel workload** — routed findings by channel, colored by cadence
   type. Flags channels whose volume justifies splitting.
3. **Adjudication queue** *(the work)* — `vw_pbi_unroutable` as a table
   grouped by vendor/product, sorted by group size descending. This page
   *is* the analysts' working loop.
4. **Registry health** *(the hygiene sweep)* — rules past `review_by`,
   correction count over time, correction share of routing.

## 8. Refresh runbook

Findings load on their own batch schedule; rules flow on merge:

1. **PR merges** — a rule lands in `registry/`; CI has already run
   `validate` + the tests + fixtures.
2. **Export** — CI runs `tools/export_registry_sql.py` → six CSVs.
3. **Reload** — truncate + bulk-insert the `reg.*` tables (and the fixture
   findings) in one transaction.
4. **Parity gate** — run the §6 query. Zero rows → commit. Any rows → roll
   back and alert; the old rules stay live.
5. **Power BI refresh** — the scheduled dataset refresh picks up the new
   routing on its next run.

## 9. Gotchas — where the twins can quietly disagree

1. **Collation vs. `LOWER()`.** The SQL forces case-insensitivity with
   `LOWER()` so it behaves identically on any collation. Keep it even on
   CI-collated servers — parity beats micro-optimisation.
2. **Keyword values are deliberately odd.** `" plc "` carries meaningful
   whitespace. The exporter emits values verbatim and a test pins this; a
   helpful `TRIM()` in the load job would silently change routing.
3. **Context operators.** The engine supports `in:` (exported as multiple
   OR rows — covered) and `not:` (no seed rule uses it; the exporter
   **fails loudly** if one ever lands, rather than mistranslating).
4. **Dialect notes.** Postgres: `CHARINDEX(a,b)` → `POSITION(a IN b)`,
   `ISNULL` → `COALESCE`, `GETDATE()` → `CURRENT_DATE`, `+` concat → `||`.
5. **The findings feed must carry context to the DB too.** Corrections only
   fire on findings whose `vm.finding_context` rows exist. If context
   enrichment (bundle manifest, image-layer attribution) happens only on
   the Python path, the SQL twin routes those findings by identity defaults
   — same rules, different data, different answers. **Enrich before the
   fork** so both consumers see identical findings.

Companion docs: [analyst-guide.md](analyst-guide.md),
[ownership-and-sources.md](ownership-and-sources.md).
