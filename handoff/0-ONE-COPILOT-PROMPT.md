# The one Copilot prompt

**Don't upload files to Copilot. Paste this into the chat, then paste your
existing report query underneath it.** That's the whole trick — Copilot can't
take our formats as files, but it handles one pasted prompt fine.

This does the single most important thing: adds **who fixes each finding** to
the report you already have. Everything else in the bundle (suppression,
evidence, playbooks) is for later and is not Copilot's job.

---

## STEP 1 — paste this whole block into Copilot

> You are helping me extend an existing Oracle-backed Power BI report. I have
> **read-only** access — you must produce a single `SELECT` query, no CREATE,
> no INSERT.
>
> Below is a routing ruleset as two inline CTEs (`ch` = fix channels with
> owners, `rl` = technology rules). I will paste my existing report query
> after this message. Your job:
>
> 1. Wrap my existing query as a CTE called `f`.
> 2. For each row, find the **first** matching rule in `rl` ordered by
>    `priority` ascending — a rule matches when its `match_value` (lowercased)
>    is contained in the row's vendor (for `VENDOR` rules) or in the row's
>    product+description text (for `KEYWORD` rules). Fold `-` and `_` to spaces
>    on both sides before comparing.
> 3. Add these columns to my rows, keeping ALL my existing columns:
>    `CHANNEL_NAME`, `OWNER_GROUP`, and `ROUTING_STATUS` = 'ROUTED' when a rule
>    matched else 'UNROUTED'.
> 4. Use only Oracle syntax: `INSTR`, `NVL`, `||`, `TRANSLATE`, `ROW_NUMBER()`.
>    Never `CHARINDEX`, `ISNULL`, `GETDATE`, `TOP`.
> 5. If you are unsure of my column names, ask me — do not invent them.
>
> Answer in the query only, minimal explanation. Here is the ruleset:
>
> ```
> ch(channel_id, channel_name, owner_group):
>   windows-endpoint      | Windows endpoints (EUC)          | EUC team
>   windows-server-onprem | On-prem Windows servers          | Windows server team
>   euc-central-bundle    | EUC central bundle               | EUC team
>   euc-user-installed    | EUC user-installed (not bundled) | Per-exception owner
>   mac-endpoint          | Mac endpoints                    | Jamf team
>   mobile-ios            | iOS / iPadOS fleet               | Mobile platform ops
>   linux-onprem          | On-prem Linux                    | Linux team
>   k8s-image             | Container base images            | Cloud image team
>   ami-rehydrate         | EC2 AMI rebuilds                 | Cloud team
>   build-dependency      | App dependencies (CI)            | Repo owner (per app)
>   internal-app          | Internally-operated apps         | App team (per app)
>   middleware            | Middleware (host-installed)      | App / hosting team
>   database              | Database servers                 | DBA team
>   network               | Network appliances               | Network engineering
>   virtualisation        | Virtualisation platforms         | Platform / infra
>   oracle-cpu            | Oracle Critical Patch Update      | Oracle platform team
>   vendor-product        | Enterprise vendor products       | Vendor product owner
>   cloud-managed         | Cloud-managed services           | Cloud team
>
> rl(priority, match_type, match_value, channel_id):
>   10 VENDOR  oracle          -> oracle-cpu
>   20 KEYWORD exchange server -> windows-server-onprem
>   20 KEYWORD sharepoint      -> windows-server-onprem
>   25 KEYWORD windows server  -> windows-server-onprem
>   30 KEYWORD windows         -> windows-endpoint
>   25 KEYWORD iphone          -> mobile-ios
>   25 KEYWORD ipad            -> mobile-ios
>   30 KEYWORD macos           -> mac-endpoint
>   35 VENDOR  apple           -> mac-endpoint
>   20 KEYWORD linux kernel    -> linux-onprem
>   25 VENDOR  red hat         -> linux-onprem
>   25 VENDOR  ubuntu          -> linux-onprem
>   25 VENDOR  suse            -> linux-onprem
>   25 VENDOR  debian          -> linux-onprem
>   30 KEYWORD office          -> euc-central-bundle
>   30 KEYWORD outlook         -> euc-central-bundle
>   30 KEYWORD chrome          -> euc-central-bundle
>   30 KEYWORD edge            -> euc-central-bundle
>   30 KEYWORD firefox         -> euc-central-bundle
>   30 KEYWORD acrobat         -> euc-central-bundle
>   28 KEYWORD visual studio   -> euc-user-installed
>   42 KEYWORD log4j           -> build-dependency
>   42 KEYWORD spring          -> build-dependency
>   42 KEYWORD struts          -> build-dependency
>   42 KEYWORD jackson         -> build-dependency
>   45 KEYWORD netscaler       -> network
>   45 KEYWORD citrix adc      -> network
>   50 KEYWORD tomcat          -> middleware
>   50 KEYWORD nginx           -> middleware
>   50 KEYWORD sql server      -> database
>   50 KEYWORD postgresql      -> database
>   50 VENDOR  cisco           -> network
>   50 VENDOR  fortinet        -> network
>   50 VENDOR  palo alto       -> network
>   50 VENDOR  vmware          -> virtualisation
>   65 KEYWORD jenkins         -> internal-app
>   70 VENDOR  sap             -> vendor-product
>   70 VENDOR  atlassian       -> vendor-product
> ```

## STEP 2 — paste your existing report query

Right after that, send:

> Here is my existing query. Wrap it as `f` and add the routing columns as
> described:
>
> ```sql
> [paste your current Power BI source query here]
> ```

That's it. Copilot returns one query with your columns plus who-fixes-it.

---

## If it still struggles

- **Give it your column names first.** Send: *"My query returns these columns:
  FINDING_ID, CVE_ID, VENDOR, PRODUCT, … — the vendor text is in VENDOR and
  the product text is in PRODUCT."* Ambiguity about column names is the #1
  reason it stalls.
- **Ask for less.** *"Just add CHANNEL_NAME and OWNER_GROUP. Skip
  ROUTING_STATUS for now."* Get one column working, then add the rest.
- **One thing at a time.** If it tries to explain everything, reply: *"Query
  only. No explanation."*
- **Adding SLA/due-date later** is a follow-up prompt, not part of this. Once
  routing works, ask: *"Add SLA_DAYS and DUE_DATE: each channel has an SLA in
  days (most 30, Windows endpoints 5, Oracle CPU 90, DMZ assets 7); DUE_DATE =
  first-seen date + SLA."*

## Why this is the whole thing

The full `1-routing-query-readonly.sql` is the same logic with more rules and
the SLA columns. If Copilot chokes on it, this compact prompt is the version
that fits — it produces the one output that matters: **every finding now shows
who fixes it.** Add more rules over time with the analyst tool
(`2-analyst-triage-tool.html`), which emits ready-made rule lines.
