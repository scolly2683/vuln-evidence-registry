# The analyst operating model — no code, ever

The hard rule: **an analyst never opens a terminal.** Everything with a
command line in this repo is run by engineering or by a scheduled job. The
analyst lives in the queue and clicks. This doc defines that split so the
solution is one a non-coder can actually run.

## Two layers, two audiences

| Layer | Who runs it | How | Examples |
|---|---|---|---|
| **Engine** | engineering / scheduled jobs | CLI, CI, cron | `enrich_findings.py`, `route`, `export_*`, `sync_suppressions.py` |
| **Analyst surface** | analysts | click / form, in tools they already use | the queue in Power BI, a "Verify" button, a "Record decision" form |

The engine's job is to make the queue *short and pre-sorted* before an
analyst sees it. The analyst's job is judgement, expressed by clicking.

## What the analyst sees (not a CLI — the queue)

By the time a finding reaches an analyst it has already been through the
scheduled backend pipeline, so the queue row already carries the answers:

```
CVE-2021-44228 · Log4j · 500 detections
   band: ACT NOW    kev: yes   epss: 0.94   public PoC: yes
   reachable (graph): 30 of 500      suppressible drafts: 470
   [ Verify the 30 ]   [ Approve 470 suppressions ]   [ Open group ]
```

Nothing there was typed by the analyst. `enrich_findings.py` (scheduled)
added the band/kev/epss/PoC tags; the graph query added reachability; the
routing engine drafted the suppressions. The analyst reads three numbers
and clicks one of three buttons.

## The three buttons — and what each is wired to

Analysts express intent; **code runs elsewhere**. In a Microsoft estate the
wiring is Power BI / Power Apps / Power Automate (no analyst coding, and
nothing new to learn):

1. **Approve suppressions** — the pre-drafted "not exploitable" verdicts
   (dead copies, wrong artifact, class-not-loaded). A Power App form shows
   the draft + evidence; the analyst picks a verdict from a dropdown and
   hits Approve. The flow appends to a request list; engineering's job turns
   the list into `propose-suppression` runs. Analyst sees: dropdown +
   Approve. That's it.

2. **Verify the residual** — the handful that are reachable / internet-
   facing. A button triggers a Power Automate flow → the backend verifier
   (tier 1/2 from `exploit-verification.md`: reachability + Nuclei +
   Interactsh) runs against the selected scope → results land back in the
   queue as callbacks (act-now findings) or clean runs (evidence). Analyst
   sees: a button and, later, a verdict. No exploit knowledge required —
   the templates are maintained by others.

3. **Record a routing decision** — for unroutable groups, the 7-field
   request form (where it goes, what matches, condition, who, why, evidence,
   re-check date) as a Power App / SharePoint form. Writes to the same
   request list; engineering converts to `propose-correction`.

## The request list is the whole interface

Everything an analyst "submits" — a suppression approval, a verify request,
a routing decision — is one row in a shared list (SharePoint list, a table,
a ticket queue; whatever you already run). That list is the only contract
between analysts and the engine:

```
analyst clicks/forms  ─▶  request list  ─▶  engineering batch (weekly, 30 min)
                                              ├─ propose-correction / -suppression
                                              ├─ validate + tests (CI gate)
                                              ├─ export SQL / VEX / scanner sync
                                              └─ reload → Power BI updates
```

No analyst touches git, Python, YAML, or a scanner console. They fill a
form; the queue changes next refresh.

## Who does what

| Task | Analyst | Engineering / you | Automated |
|---|---|---|---|
| Enrich findings with KEV/EPSS/PoC | | | ✅ nightly `enrich_findings.py` |
| Reachability from the SBOM graph | | | ✅ scheduled graph query |
| Draft suppressions for non-exploitable | | | ✅ routing engine |
| **Approve / reject a draft** | ✅ dropdown | | |
| **Request active verification** | ✅ button | | triggers backend Nuclei/OAST |
| **Record a routing decision** | ✅ form | | |
| Turn request-list rows into rules | | ✅ weekly batch | |
| Validate, export, sync, reload | | ✅ (or CI) | ✅ |

## Why this respects the "no coding" reality

- The only new analyst habit is **"decide in the form, not in the console"**
  — the same behaviour change the playbook already asks for.
- The three buttons map to the three things analysts actually do: dismiss
  noise, confirm the real ones, route the rest.
- The queue does the prioritisation, so a non-coder spends their time on the
  ~5% that needs a human, not the 95% the engine already sorted.
- If Power Platform isn't available, the fallback is even simpler: a shared
  spreadsheet or an email template as the request list. The engine doesn't
  care where the seven fields come from.

Companion docs: [analyst-guide.md](analyst-guide.md) (what the fields mean),
[exploit-verification.md](exploit-verification.md) (what the Verify button
runs), [rollout-plan.md](rollout-plan.md) (order to stand this up).
