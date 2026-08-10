# Copilot prompts — paste these

Copilot is good at one well-specified thing at a time and bad at "build me a
report". These prompts are written to play to that.

---

## 1. THE CONTEXT PRIMER — paste this first, once per session

Everything below the line goes into Copilot before you ask it anything else.

---

> I'm building a vulnerability-management report in Power BI on top of an
> Oracle database that I have **read-only** access to. I cannot create tables
> or views — only SELECT.
>
> **What I'm doing:** every vulnerability finding from our scanners (Qualys
> on-prem, Wiz cloud, GitHub dependency alerts) needs to be routed to a "fix
> channel" — the delivery mechanism that will actually ship the fix (e.g.
> Windows Patch Tuesday, the EUC monthly bundle, the Oracle quarterly CPU,
> the container base-image rebuild, an internal app team). Each channel has
> an owning team and an SLA in days. Internet-facing (DMZ) assets get a
> shorter 7-day SLA.
>
> **How routing works:** a list of technology rules maps text to a channel.
> Each rule has a priority (lowest number wins), a match type
> (VENDOR = substring on the vendor column, KEYWORD = substring on
> product+description, PURL_PREFIX = the package URL starts with a string),
> a match value, and a channel id. For each finding, the first matching rule
> by priority decides the channel. If no rule matches, the finding is
> UNROUTED — that's the analyst queue, and each one gets adjudicated into a
> new rule so the queue shrinks over time.
>
> **My source query** is a single Oracle SELECT with the channels and rules
> inlined as CTEs (`ch` and `rl`), joined to my findings table, using
> ROW_NUMBER() to take the first match. It returns these columns, which is
> what my Power BI model sees:
>
> FINDING_ID, CVE_ID, ASSET_ID, VENDOR, PRODUCT, SEVERITY, SOURCE
> ('QUALYS'|'WIZ'|'GITHUB'), ZONE ('DMZ' when internet-facing), FIRST_SEEN
> (date), ROUTING_STATUS ('ROUTED'|'UNROUTED'), CHANNEL_ID, CHANNEL_NAME,
> OWNER_GROUP, DECIDED_BY_RULE, SLA_DAYS (number), DUE_DATE (date),
> AGE_DAYS (number), OVERDUE_FLAG ('Y'|'N').
>
> **The metric that matters** is the percentage of findings that are
> UNROUTED, tracked over time — it should fall as analysts add rules.
>
> Answer with Oracle SQL or DAX as appropriate. Keep to standard Oracle
> syntax (INSTR, NVL, ||, TRUNC(SYSDATE)) — no SQL Server functions.
> Acknowledge you've got this and wait for my next question.

---

## 2. Adapting the query to your real schema

> Here is my findings table definition:
>
> [paste your DESCRIBE / column list here]
>
> In the query I described, the `f` CTE currently selects FINDING_ID, CVE_ID,
> ASSET_ID, VENDOR, PRODUCT, DESCRIPTION, PURL, DETECTION_ID, FIRST_SEEN,
> SEVERITY, SOURCE, ZONE. Rewrite just that `f` block to use my real column
> names. Where I have no equivalent column, use NULL with an explicit CAST so
> the query still runs. Show me only the `f` block.

If you don't know your columns, ask it first:

> Write an Oracle query that lists the column names and data types of the
> table [SCHEMA].[TABLE], ordered by column id.

## 3. Measures — one at a time

> Write a single DAX measure for [Findings / Unrouted / Unrouted % / Overdue /
> Overdue % / average AGE_DAYS] against the table described earlier. Include
> the recommended format string. Explain in one sentence what it does.

Then, when you need a trend:

> I have a Date table related to FIRST_SEEN. Write a DAX measure that gives
> Unrouted % for the previous month, so I can show month-on-month movement.

## 4. Visuals — ask for a decision, not a build

> I want to answer this question on a Power BI page: "[e.g. which owner teams
> have the most overdue findings]". Given the columns described earlier,
> recommend ONE visual type, tell me exactly which fields go in which field
> well, how to sort it, and one formatting setting that makes it readable.
> Do not suggest more than one visual.

## 5. Working the queue

> Write an Oracle query against my routed query (as a subquery or CTE) that
> returns the UNROUTED findings grouped by VENDOR and PRODUCT, with a count
> of findings, a count of distinct CVEs and a count of distinct assets,
> ordered by finding count descending, top 25. This is my analyst work queue.

Then, to turn the answers into rules:

> For these products: [paste top unrouted products], write one
> `UNION ALL SELECT 'r-<name>',<priority>,'KEYWORD','<text>','<channel-id>'
> FROM DUAL` line each, matching the rule CTE format I described. Valid
> channel ids are: windows-endpoint, windows-server-onprem,
> euc-central-bundle, euc-user-installed, mac-endpoint, mobile-ios,
> linux-onprem, k8s-image, ami-rehydrate, build-dependency, internal-app,
> middleware, database, network, virtualisation, oracle-cpu, vendor-product,
> cloud-managed. Ask me which channel if it's ambiguous rather than guessing.

## 6. Troubleshooting prompts that work

> This Oracle query returns more rows than my findings table has. Explain why
> a join to a rules CTE can duplicate rows and how ROW_NUMBER() with a
> partition prevents it.

> My Power BI refresh is slow on this query. Given it does substring matching
> with INSTR across a rules CTE, suggest three changes that reduce the work
> Oracle does, in order of impact.

> My date-based visual shows nothing. I have FIRST_SEEN and DUE_DATE as dates
> and a separate Date table. Walk me through the relationship setup and
> "Mark as date table" step.

---

## Rules for getting good answers out of Copilot

1. **Re-paste the context primer** whenever you start a new chat. It forgets.
2. **One measure, one visual, one query per ask.** Compound requests are
   where it invents columns.
3. **Say "Oracle"** every time. Left alone it drifts to SQL Server syntax
   (`CHARINDEX`, `ISNULL`, `GETDATE`) that won't run.
4. **Make it ask, not guess** — the phrase "ask me rather than guessing" in a
   prompt genuinely reduces invented column names.
5. **Sanity-check every count.** If a change makes your total findings go up,
   you have a join fan-out, not a better report.
