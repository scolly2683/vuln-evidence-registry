# Bringing this to work — the simple version

Everything else in `docs/` is reference. This page is the plan. Four steps,
each shippable on its own, each with a visible result. No big bang, no new
infrastructure until step 3.

## Step 1 — One meeting: agree the channel map (week 1)

Take the channel table in `estate-blueprint.md` §2 to the teams named in it
(EUC, Windows server, Jamf, mobile ops, Linux, cloud image, network, DBA).
For each channel confirm three facts: **the owner, the cycle, the SLA**
(including the DMZ 7-day rule). Write the answers into a private copy of
`registry/` — that's the whole config change; the YAML in the blueprint is
ready to paste.

**Result:** a routing config that speaks your org's names.
**Effort:** one workshop + an hour of YAML.

## Step 2 — Route one month read-only, on a laptop (week 1–2)

Export one month of findings from Qualys/Wiz/GitHub to CSV or JSONL
(minimum columns: id, cve_id, vendor, product, description; qid and purl
where available). Then:

```bash
pip install pyyaml && pip install -e .
python -m routing_registry route --registry registry --findings month.jsonl --stats
```

Nothing is ticketed, nothing syncs anywhere — you just read the output.
Three numbers matter: what routed (sanity-check the biggest channels), the
**unroutable list grouped by product** (your first adjudication queue —
take the top 10 groups, decide each once, add the rule), and what screens
caught.

**Result:** a baseline `unroutable_pct` and your first ten org rules.
**Effort:** a few hours a week; no approvals needed — it's read-only.

## Step 3 — Kill the QID storms with the suppression registry (week 2–4)

This is the fastest visible win because the pain is current. Pick the two
worst detection clusters (log4j 1.x, Spring4Shell). For each:

1. Verify **one instance per QID** properly (SBOM graph / manual).
2. Record the verdict — one command, group-level, evidenced, expiring:

```bash
python -m routing_registry propose-suppression --registry registry \
    --match qid=376157,376178 --verdict false_positive \
    --decided-by you --trigger "log4j 1.x QID cluster" \
    --evidence "Log4j 1.x lacks the JNDI lookup class; version-string match only" \
    --review-by 2027-08-01
```

3. Commit the diff (that's the approval record), then mirror it manually in
   Qualys (search-list exclusion) and Wiz (ignore rule) — automation of the
   sync comes later; the registry is already the audit trail today.
4. Regenerate the OpenVEX document (`python tools/export_vex.py ...` — see
   `docs/vex-export.md`). That one file is the shareable, standard-format
   statement of what we don't act on and why.

**Result:** thousands of detections cleared with two auditable records,
and every future "is this suppressed and why?" question has an answer in
git.
**Effort:** the verification is work you'd have to do anyway — this just
makes it count once.

## Step 4 — Wire the database and Power BI (week 4+)

Only now touch shared infrastructure. Hand `docs/sql-powerbi.md` to
whoever owns the in-house DB: the tables, views, and parity gate are
copy-paste, and `tools/export_registry_sql.py` produces the load files.
First report page: **unroutable % by run** (the convergence line) and the
**worklist** (blueprint §7). The currency queue → enforcement feed follows
once channels' SLAs from step 1 are in the channel table.

**Result:** the monthly picture in Power BI, and the "assets behind"
catcher feeding enforcement.

## What NOT to do yet

- Don't let routing drive ticket assignment until a full monthly cycle has
  run clean read-only.
- Don't automate the Qualys/Wiz suppression sync until you have ~10 manual
  suppressions and the shape is stable.
- Don't build the Neo4j enrichment pipeline first, even though it's the
  biggest long-term win — steps 1–3 deliver value without it and teach you
  exactly which enrichment matters (start with purl-on-runtime-findings
  when you get there).

## The weekly rhythm once running

| When | What | Who |
|---|---|---|
| Per batch | route, work top unroutable groups → rules | analyst |
| Weekly | propose corrections/suppressions from the week's misroutes and FP clusters | analyst + registry owner approves diffs |
| Monthly | `validate` hygiene sweep: re-verify or retire rules past `review_by` | registry owner |
| Monthly | check the convergence line; if flat, the queue isn't becoming rules | you |
