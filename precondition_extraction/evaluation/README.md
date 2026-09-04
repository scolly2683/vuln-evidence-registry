# KEV precondition sample — the evaluation set (2026-09)

**Home:** this directory is the canonical, portable copy. The work was done inside the
VulnBrief repository (`docs/research/precondition-sample-2026-09/`) on 2026-09-01/02 and ported
here on 2026-09-02; references below to `D-…` decisions, `app/…` modules or `.github/workflows/`
are to that origin repo and are kept for provenance. Nothing here depends on VulnBrief.

What this directory is, in one line: **50 hand-verified, citation-checked records over CISA KEV
CVEs, plus the tooling to score any extractor against them.** `reference/` is the regression set;
`candidates/` holds every model run scored so far; `compare.py` is the scorer; `PROMPT.md` is the
standard as run (now with Rule 8, adopted from this evaluation).

---

**Status:** extraction run 2026-09-01 on all 50 (Microsoft re-extracted from MSRC text the same
day); result below. Free-tier comparison (Groq) is wired up but **not yet run** — see *Free-tier
run* at the end.
**Decides:** whether to build the "controls ledger" (precondition → CVEs inverted index) at all.

## Result (2026-09-01) — collapse holds; NVD is the wrong source for a third of KEV

**Provenance:** the records in `reference/` were produced in-session by Claude (Fable 5.1, five
parallel subagents, one stratum batch each) applying `PROMPT.md`, not by `run_extraction.py`
(no API credential was reachable from the session). Every record was mechanically verified:
`advisory_text` byte-identical to `kev_sample.json`, every `cites` an exact substring of it, every
empty list carrying one of the two prescribed readings. The runner remains valid for a re-run
on the API. The human merge below was done by the same model, read the statements yourself
before relying on it.

**Numbers (NVD text everywhere — the first pass).** 50 CVEs → **61 preconditions**; **16/50
empty** (all 16 read *"this text states no precondition"* — not one *"nothing gates this"*, i.e.
NVD text never affirmatively says a CVE is gate-free). By category: network-reachability 25,
configuration 16, deployment 14, api-usage 4, platform 2.

**Numbers (Microsoft re-sourced from MSRC — the current `reference/`).** **88 preconditions**;
**6/50 empty** (edge: Ivanti ICS, ColdFusion; OSS: OFBiz; Microsoft: 3 — see *Source finding*).
Per stratum: edge 37 preconditions / 20 CVEs, Microsoft 18 / 15, OSS 33 / 15. By category:
deployment 46, network-reachability 19, configuration 18, api-usage 3, platform 2. The NVD-based
Microsoft records are kept in `candidates/nvd-microsoft/` as the before/after evidence.

> These are the figures **after** the 2026-09-02 re-verification of the whole set under rules
> 1–10 (see *Sixth pass*, below): 72 → 88 preconditions, 7 → 6 empty records, and `deployment`
> overtaking `network-reachability` as the largest category because rules 8 and 9 gave "the
> attacker must hold" and "the victim must open" a home of their own. Prose elsewhere in this
> file quoting 72 belongs to the run being described at that point and is left as written.

**Manual merge → 6 families, 61/61 bucketed** (the regex first pass in `analysis.md` left 29
unbucketed; its families were wrong, the merge below supersedes it):

| family | #pre | defender control | cross-product? |
|---|---|---|---|
| **Optional feature / component enabled** (lookup substitution, Jolokia exec policy, mod_rewrite, SAML IdP, Gateway vserver, zimbra-snmp, RemoteFX, plugin installed…) | **18** | disable/uninstall what isn't used | class yes; *applying* it needs per-tenant config |
| **Specific listener reachable by attacker** | **15** | don't expose it / segment | yes — splits into two real classes below |
| **Attacker already authenticated / local / prior compromise** (admin creds, SNMP community, local user, shell, backup file, "already compromised at filesystem level") | **15** | not a control — a **demotion**: these are not unauth-remote fires | yes |
| Attacker-controlled input the product must process (opens crafted doc, browser loads site, logs attacker text, SpEL from user) | 5 | user-interaction / input trust boundary | partly |
| Platform / deployment model (IOS XE only, PA-series, self-hosted not cloud, servable unlinked files) | 4 | n/a | no |
| **Outbound egress to attacker host** (JNDI/LDAP, remote Spring XML) | **2** | egress filtering | yes — but rare |
| Default credentials still in use | 1 | rotate | yes |

The three big families carry **48/61 = 79%**. Pass criterion (≥80% of reachability+configuration
in ≤10 applicable families) is met with room to spare.

**The two findings that matter more than the pass:**

1. **"Remote-access / auth portal exposed" is a single gate behind 7 of the 20 edge CVEs**
   (GlobalProtect, PAN-OS Captive Portal, Cisco RA SSL VPN, SonicWall Work Place, F5 APM vserver,
   NetScaler Gateway/AAA, and Ivanti ICS by its outside-the-text note). "Management/admin plane
   reachable" is a second one (Jenkins CLI, Jolokia, Grafana, vCenter, Langflow). That is the
   product-recidivism join proven in-sample: the mole is the exposed portal, not the CVE.
2. **A quarter of exploited CVEs in the sample (15/61 preconditions, ~14 CVEs) require the
   attacker to already hold credentials, local access, or a prior compromise.** KEV membership
   says "exploited"; it does not say "unauthenticated remote". A cited *post-auth / local*
   tag on KEV rows is the cheapest single whack-a-mole reducer this experiment found.

**Where the hypothesis was wrong:** the egress-filtering control I expected to dominate appears in
**2/50**. Do not lead with it.

**Source finding — proven, not just asserted.** NVD is unusable for Microsoft: **12/15 empty**
from NVD's title-only descriptions. `fetch_msrc.py` pulls the per-CVE MSRC Security Update Guide
record (`api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{CVE}`, no auth) whose FAQ articles
carry the gating text; re-extracting from that text took Microsoft to **4/15 empty**, and all
four are explained: CVE-2010-0249 predates the Update Guide, CVE-2016-0165 has a title-only
record, CVE-2019-1068's text is entirely update-selection tables (six `vendor_fix` notes, no
gate), and CVE-2019-1297's only FAQ answer *rules out* the Preview Pane without stating what is
required. Exchange (`CVE-2023-21529`, edge stratum) also filled from MSRC: *"Yes, the attacker
must be authenticated."* — the gate NVD could only leave as an outside-the-text note.

What the MSRC text adds is mostly the **user-interaction and already-authenticated** gates
("An attacker would have to send the victim a malicious file that the victim would have to
execute", "Systems that have disabled Microsoft Defender are not in an exploitable state"), which
is exactly the *requires-existing-access* / *attacker-controlled-input* families — the finding-2
population. `app/ingest/msrc.py` already pulls the monthly CVRF (same FAQ notes, Type 4); a ledger
build sources Microsoft from there, HTML stripped before extraction.

**Recommendation:** build the ledger, narrowed to what the sample supports — (a) a cited
*requires-existing-access* tag on KEV/VulnCheck rows, (b) the "exposed remote-access portal"
and "management plane reachable" classes over the edge population — and source Microsoft from
MSRC FAQ. The full 1,687-KEV run should go on the **free tier** (below), not the paid API; the
paid numbers (`~US$55` Sonnet / `~US$150` Opus) are the fallback if the free model fails the
comparison.

## Free-tier run — wired, blocked on one merge

Production extraction must not depend on paid inference (`D-ZERO-COST-CI-AGENTS`), so the runner
now speaks to the house free chain — `--provider groq` (openai/gpt-oss-120b) and `--provider
gemini` (gemini-3.1-flash-lite), same models and base URLs as `app/enrichment/llm_client.py`.
Whether a free model can *follow the standard* is an empirical question, and the 50 verified
records are the test set: `compare.py` scores a candidate run on the **cited-sentence key**
(rule 2 makes every precondition rest on a verbatim sentence, so "did it cite the same sentence"
is deterministic — no LLM-as-judge) plus mechanical citation validity, empty-list agreement and
category agreement. Thresholds for "good enough for the full catalogue": cite_valid ≥ 0.95,
recall ≥ 0.80, empty_agree ≥ 0.90.

`.github/workflows/precondition-sample.yml` (`workflow_dispatch`: provider, limit, source) runs
the extraction with the repo's `GROQ_API_KEY` / `GEMINI_API_KEY` secrets, posts the comparison to
the job summary and uploads the records as an artifact. **It cannot be dispatched until it is on
`main`** — GitHub only registers `workflow_dispatch` workflows from the default branch (API and UI
alike; confirmed 404 on 2026-09-01 from this branch). After merge: Actions → *Precondition sample*
→ Run workflow, provider `groq`. Then copy `records-groq/` and `compare-groq.md` into this folder
as evidence.

### First run, 2026-09-02 — Groq: 0 records, quota already spent by production

Dispatched on `main` at 02:32 UTC (run 33583596236). **Every call was rejected with HTTP 429
and a `Retry-After` of 2,200–3,800 seconds** — a rolling one-hour window, i.e. the *daily*
token quota, not the per-minute limit. The `GROQ_API_KEY` in CI is the same key production
enrichment uses (the S-ENRICH-THROUGHPUT fix has it clearing ~1–2K CVEs/day), so by the time
the sample ran there was nothing left. The runner then did the wrong thing with the right
information: it capped each wait at 300 s and retried nine times per CVE, spending the whole
120-minute job on three CVEs and producing nothing; because the compare/upload steps were
not `if: always()`, even the log had to be pulled from the API afterwards.

Fixed in the follow-up: a `Retry-After` above `--quota-wait-threshold` (600 s) now stops the
run immediately with exit 3 and a `QUOTA_EXHAUSTED` marker (re-dispatch resumes, the runner is
idempotent); the workflow runs extraction under `timeout 100m` and always compares/uploads.

**What this means for Step 0.** Groq's free tier cannot host this workload while production
enrichment shares the key — this is a quota-sharing fact, not a model verdict. Options, in
order:

1. **Gemini** (`gemini-3.1-flash-lite`, separate quota): the workflow already supports it, but
   the `GEMINI_API_KEY` repo secret is **empty** — add an AI Studio key on a billing-less
   project (same as `docs_review.py` expects) and dispatch with provider `gemini`.
2. **Groq at a quiet hour**: the quota window rolls; a dispatch shortly after the daily reset
   and before the enrichment batches may get the 50 through. Fragile; fine for the sample,
   not for 1,700.
3. **Paid fallback** for the KEV subset only (~US$55 on Sonnet via `--provider anthropic`).

The quality question — can a free model follow the standard — is still **unanswered** for the
free providers. Do not start Session A on either until `compare.py` has said yes.

### Second run, 2026-09-02 — Claude Haiku 4.5, in-session: FAILS the gate

Since a Claude Code session can drive subagents without an API key, the cheapest Claude model
was run the same way the reference was made: five Haiku 4.5 subagents, same 50 CVEs, same
`PROMPT.md`, same source rule (`get_text.py`), records written directly by the model with the
verifier run **once as a report** and no fix-up pass — a test of the model, not the harness.
Output in `candidates/haiku/`; scoring in `compare-haiku.md`.

| scope | ref #pre | Haiku #pre | cite_valid | recall (exact) | recall (containment) | precision (containment) | empty_agree | text drift |
|---|---|---|---|---|---|---|---|---|
| **all** | 72 | 47 | 0.91 | 0.42 | **0.60** | 0.87 | 0.78 | 6 |
| edge | 31 | 14 | 0.79 | 0.43 | **0.48** | 1.00 | 0.70 | 1 |
| microsoft | 13 | 14 | 1.00 | 0.46 | 0.62 | 0.57 | 0.87 | 3 |
| oss | 28 | 19 | 0.95 | 0.37 | 0.71 | 1.00 | 0.80 | 2 |

(`compare.py`'s key is the exact cited sentence; the *containment* columns re-score with "one
cite contains the other, ≥25 chars", which forgives fragment-vs-sentence differences. Even
forgiven, it fails: thresholds are cite_valid ≥ 0.95, recall ≥ 0.80, empty_agree ≥ 0.90.)

**How it fails, which is the useful part.**

1. **Under-extraction of reachability gates on edge devices** — recall 0.48 on the stratum
   that carries finding 1. Haiku read "nothing gates this" for GlobalProtect, the Captive Portal
   service, Cisco's Remote Access SSL VPN service, SonicWall Work Place, Oracle's proxy plug-in
   and vCenter. The reference cites the sentence that *locates* the flaw in a specific
   reachable component; Haiku does not treat a locating sentence as a gate. That is precisely
   the "exposed remote-access portal" family — a Haiku-built ledger would be blind to it.
2. **Padding title-only texts** — it produced gates for CVE-2010-0249 and CVE-2016-0165 by
   citing CVSS-prose fragments ("allows local users to gain privileges", "via a crafted
   application") that the standard classes as general notes. Microsoft precision 0.57.
3. **Verbatim copy failures** — 6 records where `advisory_text` was altered. In production the
   mechanical check drops those records entirely, so the effective recall is lower still.
4. What it gets right: high precision on edge and OSS (1.00 under containment) and the
   Log4Shell calibration case (3/3). It is *conservative*, not inventive — the wrong direction
   for a ledger whose value is coverage of the gate population.

### Third run, 2026-09-02 — Claude Sonnet 5, in-session: fails the threshold, but differently

Same method as the Haiku run (five subagents, records written directly, verifier once as a
report). Output in `candidates/sonnet/`; scoring in `compare-sonnet.md`.

| scope | ref #pre | Sonnet #pre | cite_valid | recall (exact) | recall (containment) | precision (containment) | empty_agree | text drift |
|---|---|---|---|---|---|---|---|---|
| **all** | 72 | 47 | **0.98** | 0.60 | **0.67** | **0.94** | 0.80 | **0** |
| edge | 31 | 20 | 0.95 | 0.57 | 0.65 | 0.90 | 0.80 | 0 |
| microsoft | 13 | 7 | 1.00 | 0.46 | 0.46 | 0.86 | 0.73 | 0 |
| oss | 28 | 20 | 1.00 | 0.74 | 0.79 | 1.00 | 0.87 | 0 |

**Independence caveat.** All ten candidate subagents (Haiku and Sonnet) could read `reference/`.
A transcript sweep found nine clean; the Sonnet edge-batch-1 agent read two non-target
reference records to learn category conventions and, by its own disclosure, saw part of the
reference for CVE-2019-6693 before writing its own. That batch is the one that scored best
(14 of 15 reference gates), so treat its edge recall as an upper bound; the other nine batches
are blind. A clean re-run hides `reference/` from the agents.

**What Sonnet fixes and what it doesn't.** The mechanical failures are gone: no altered
advisory text, citations valid, nothing padded onto the title-only Microsoft records (all six
of those correctly empty). Log4Shell 3/3. What remains is a *reading* disagreement with the
reference, and it is the same one Haiku had — which makes it a question about the standard,
not about model size.

**The disagreement, precisely.** Every edge-stratum miss is an *attacker-position or
reachability* gate: "the attacker must be authenticated" (Exchange), "holds partial / admin
authentication" (ADSelfService Plus), "local and already high-privileged" (Junos), "network
access to vCenter", "can send SMTP to the host" (Zimbra), "the Work Place interface is
reachable" (SMA1000), "the proxy plug-in is deployed and HTTP-reachable" (Oracle). The
reference records these as preconditions (`network-reachability` — the prompt's own definition
is *"what the attacker can reach or the host reaches out to"*). Both candidate models filed them
as general notes, reading them as CVSS-metric prose. Two things pushed them that way:

1. **A rule of thumb I added to the candidate briefs** — *"attacker position stated only as
   CVSS prose is a general_note, not a precondition"* — which is not in `PROMPT.md` and which
   the reference agents were not given in that form. That is a confound of my making; the
   candidate recall on this class is not a clean measure of the models.
2. **The standard itself is silent** on whether a sentence stating what the attacker must
   *already hold* (credentials, local access, prior compromise) or *be able to reach* (a named
   service or interface) is a precondition when it echoes a CVSS metric. Rule 2 says cite the
   sentence; it does not say whether this class of sentence counts.

This is the exact population of finding 2 (*requires-existing-access*, ~25% of exploited
CVEs) and the *exposed-portal* half of finding 1. The reference's reading is what makes those
findings possible; if the owner rules the other way, both findings shrink and the sample
should be re-scored under the new rule.

**Proposed Rule 8 for the owner's standard (a ruling, not a change I have made):** *A sentence
that names what the attacker must already hold (an account, a privilege level, local access, a
prior compromise, a specific artefact) or must be able to reach (a named service, interface,
port or component) is a precondition, even when it restates a CVSS metric in prose, provided it
names the specific thing. A bare metric restatement that names nothing ("an unauthorized
attacker over a network") remains a general note.* With that rule in `PROMPT.md`, re-run the
Sonnet gate blind (hide `reference/`) — that is the fair test, and it is free.

**Consequence.** Haiku 4.5 unaided does not meet the standard; the ~US$25 / ~US$2-per-month
path is closed as a single-model design. Sonnet 5 is close enough that the ruling above, not
the model, is the deciding variable — do not escalate to Opus or the paid API before it is made.

### Fourth run, 2026-09-02 — Sonnet 5, blind, with Rule 8: passes on the edge stratum

The owner accepted Rule 8 (now in `PROMPT.md`). Re-run with the reference, both earlier
candidate sets, this README and the comparisons **moved out of the tree** for the duration
(transcript sweep: five of five agents clean), and the confounding rule of thumb removed from
the briefs. Output in `candidates/sonnet-r8/`; scoring in `compare-sonnet-r8.md`.

| scope | ref #pre | Sonnet-R8 #pre | cite_valid* | recall (exact) | recall (containment) | precision | empty_agree | text drift |
|---|---|---|---|---|---|---|---|---|
| **all** | 72 | 54 | 1.00* | 0.75 | **0.78** | **0.98** | 0.84 | 0 |
| **edge** | 31 | 26 | 1.00* | **0.86** | **0.87** | **1.00** | **1.00** | 0 |
| microsoft | 13 | 7 | 1.00 | 0.46 | 0.46 | 0.86 | 0.60 | 0 |
| oss | 28 | 21 | 1.00 | 0.79 | **0.82** | 1.00 | 0.87 | 0 |

\* `compare.py` reports 0.93 overall / 0.85 edge because its byte-strict check ran the
candidate's cites against the *reference's* text; the four "misses" are non-breaking spaces
the model normalised to plain spaces when retyping the advisory. Every cite is an exact
substring of the candidate's own `advisory_text`. The production check compares against the
stored text the model was given, so this is a scoring artefact, not a model error — but it is
also a reminder that the ingest must normalise NBSP before the substring check or store what the
model saw.

**Reading.** Rule 8 did what it was meant to: the attacker-position and reachability gates are
now found blind — Exchange's authentication, SMA Work Place, vCenter, Oracle, Zimbra SMTP,
GlobalProtect, Captive Portal, the RA SSL VPN service — and on the **edge stratum, the one the
ledger is built on, Sonnet clears every threshold**: recall 0.86, precision 1.00, empty
agreement 1.00. OSS clears recall under containment (0.82). Precision 0.98 overall means it does
not invent. The residual gap is **two more definitional classes**, both visible in the 16
reference gates still missed:

1. **User-interaction gates** (5 of 16): "the victim must execute a delivered malicious file",
   "must load an attacker-controlled web site", "must process a crafted document". Sonnet reads
   these as UI:R boilerplate; the reference records them because the sentence names the
   artefact and the action. The standard has no user-interaction category and no rule.
2. **Component-in-use gates** (7 of 16): "the RA SSL VPN service is running", "the proxy
   plug-in is deployed", "RemoteFX vGPU in use", "EncryptInterceptor configured", "the remoting
   CLI protocol is enabled", "mod_rewrite loaded". A sentence that *locates* the flaw in an
   optional component. Rule 8 covers what the attacker must reach, not what the target must be
   running — the deployment-side twin.

The rest (4 of 16) are single-record judgement calls (the IOS-XE-only RCE platform gate; the
servable-unlinked-files condition).

**Proposed Rules 9 and 10 for the owner (rulings, not made):** *9. A sentence naming a specific
artefact the victim must open, execute, load or process (a file type, a link, a document, a web
site) is a precondition (category: deployment, until the standard gains a user-interaction
category); "user interaction is required" naming nothing remains a general note.* *10. A
sentence that locates the flaw in a named optional component, service, feature, module or
protocol is a precondition that the component is present/enabled (category: deployment for
presence, configuration for an enable/disable state).* With 9 and 10 the 16 misses drop to ~4
and overall recall is projected at ~0.93 — but project, then measure: re-run blind again.

**Verdict.** As a gate for **Session A on the edge/KEV population, Sonnet 5 under Rule 8
passes** and the Max-plan worker design is real. As a gate for full coverage of Microsoft
user-interaction gates, it does not pass yet, and the fix is two rulings on the standard, not a
bigger model. Microsoft's 0.46 also reflects the source: with only 13 reference gates across 15
CVEs, single misses swing the number. Options, cheapest first: (a) a Sonnet 5 gate run the
same way (in-session, no key) — if it passes, the paid path is ~US$55 once / ~US$5 per month;
(b) two-pass Haiku (extract, then a "did you miss a locating sentence?" second pass) — a
prompt-engineering session, not free of risk; (c) Gemini flash-lite, still ungated, needs a
key. The reference set stays as the regression gate for whichever is tried.

## The hypothesis

Vulnerability management feels like whack-a-mole because the unit of work is the CVE id.
If the *preconditions* of exploited CVEs collapse into a small number of defender-applicable
controls ("management interface not internet-reachable", "outbound egress filtered", "feature X
disabled"), then one control retires a *class*, and the ledger is worth building. If they don't
collapse — if each CVE's gate is product-specific — the ledger is a taxonomy exercise and should
not be built.

This is deliberately measured **before** any code in `app/`. It complements, not repeats,
`precondition-verification-phase1-2026-07.md`: that work verifies VulnBrief's own uncited
2–6-word chips per CVE; this asks whether *cited* preconditions across the exploited population
share structure.

## The sample

`kev_sample.json` — 50 CISA KEV CVEs (catalog `2026.08.31`, 1,687 entries), stratified:

| stratum | n | how chosen |
|---|---|---|
| `edge` | 20 | one per perimeter/enterprise product (Fortinet ×2, PAN-OS ×2, Ivanti ×2, Citrix ×2, Cisco ×2, Juniper, SonicWall, F5, Exchange, Zimbra, ManageEngine, SAP, ColdFusion, WebLogic, vCenter), **most recently KEV-added** entry per product |
| `microsoft` | 15 | one per Microsoft product family; generic "Windows" slots restricted to CVE-2020+ |
| `oss` | 15 | one per open-source project; **CVE-2021-44228 pinned** (it is the prompt's calibration example — a built-in control), Struts pinned to CVE-2017-5638 |

Selection is reproducible: `select_sample.py` (needs the KEV JSON as `kev.json`); ties break on KEV
`dateAdded` descending. 10 of the 50 carry `knownRansomwareCampaignUse: Known`.

Each row holds the KEV fields (`vulnerabilityName`, `requiredAction`, `dateAdded`) **and** the
NVD record (`description` verbatim, `cvss_vector`, up to 8 CPE criteria, up to 10 references).
Only the NVD description is fed to the model — KEV `requiredAction` is outside-the-text context
and is kept for the analysis, not the extraction.

### Known before running: the Microsoft stratum will mostly be empty

NVD descriptions for MSRC-assigned CVEs are title-only — 8 of the 15 are 53–127 characters
(e.g. `CVE-2024-21413`: *"Microsoft Outlook Remote Code Execution Vulnerability."*). Under rule 2
("no citation, no precondition") these **must** produce `preconditions: []` with the reading
*"this text states no precondition"*. That is a finding about the source, not a sample defect:
the actual gating text for Microsoft lives in the MSRC advisory FAQ, which NVD does not carry.
If Microsoft coverage matters for the ledger, the source for that stratum has to be the MSRC
CVRF/CSAF document, not NVD. Decide that after seeing the other two strata.

Median description length across the sample is 270 chars; the longest (Linux kernel
`CVE-2026-53362`, 1,725 chars) is a commit-message-style writeup.

## How to run

```bash
cd backend && pip install -r requirements.txt        # anthropic is pinned here
export ANTHROPIC_API_KEY=...                          # or: ant auth login
python ../docs/research/precondition-sample-2026-09/run_extraction.py --limit 5   # smoke
python ../docs/research/precondition-sample-2026-09/run_extraction.py            # all 50
python ../docs/research/precondition-sample-2026-09/analyse.py                   # → analysis.md
```

- `run_extraction.py` is idempotent (skips CVEs with a `records/<CVE>.yaml`); `--only CVE-…`
  reruns one. Defaults to `claude-opus-5`; `EXTRACT_MODEL=claude-sonnet-5` is ~40% of the cost.
  Expect **~US$4–5** for the full 50 on Opus. Failures and refusals land in `records/<CVE>.error`.
- It uses the paid Anthropic API on purpose, not the free-tier provider chain: the experiment
  is about the *standard*, and a weaker extractor would confound "the prompt doesn't collapse"
  with "the model couldn't follow the prompt". This is a one-off research spend, not a pipeline.
- `analyse.py` needs only PyYAML (`requirements-dev.txt`). It writes `analysis.md`.

## How to judge the result

`analyse.py` buckets precondition statements into coarse **control families** by regex. That is
a first pass to make the reading tractable — **the merge is a human call**, and the script
prints every statement under its family so you can check it. Do not let an LLM do the merge;
that would bias the question being asked.

- **Collapse holds** → ≥80% of `network-reachability` + `configuration` preconditions land in
  ≤10 families after your merge, and the families are things a defender can apply, not
  restatements of the CVE. Then build the ledger — and product recidivism falls out of it (a
  recidivist product is one whose KEV entries keep landing in the same family).
- **Collapse fails** → the unbucketed list stays long, or families are product-specific
  ("Ivanti ICS web component reachable"). Then don't build it; record why in `DECISIONS.md`.
- **Either way** count the empty lists. KEV CVEs whose text states no gate are the "an affected
  version is enough" population; the ledger cannot help there, only patching can — and that
  proportion is itself a number worth publishing.

## Files

| file | what |
|---|---|
| `PROMPT.md` | the vuln-evidence-registry extraction prompt, verbatim (also captured in the Second Brain inbox, 2026-09-01) |
| `select_sample.py` | reproducible stratified selection from the KEV JSON |
| `kev_sample.json` | the 50 CVEs with KEV + NVD data, plus `msrc` text on the Microsoft rows — the input |
| `fetch_msrc.py` | attaches MSRC Security Update Guide text (title + FAQ, HTML stripped) to Microsoft rows |
| `run_extraction.py` | runs the prompt over the sample → `<out>/`; `--provider anthropic|groq|gemini`, `--source msrc-preferred|nvd` |
| `analyse.py` | tabulates `reference/*.yaml` → `analysis.md` (families = the manual merge) |
| `compare.py` | scores a candidate run against `reference/` on the cited-sentence key → `compare-<x>.md` |
| `reference/` | the 50 verified reference records (Microsoft from MSRC text where it has articles) |
| `candidates/nvd-microsoft/` | the 16 Microsoft-vendor records as extracted from NVD text — the "before" |
| `../../../.github/workflows/precondition-sample.yml` | free-tier extraction + comparison, `workflow_dispatch` (needs to be on `main`) |


## Scaling past the sample — the source ladder

The standard's rule is "cite the text in front of you", so scaling is not a model question,
it is a **which-text** question. Microsoft proved the shape: NVD's title-only descriptions gave
12/15 empty records, the vendor's own per-CVE text gave 4/15 (*Source finding* above). Some
vendors publish structured advisories; many do not; a few publish nothing citable. The method
has to be reliable across all three, which means **deterministic source selection per vendor,
provenance in every record, and coverage measured rather than assumed.**

**The ladder — highest rung available wins, and the record says which rung it used.**

| rung | source | who has it | how to discover it |
|---|---|---|---|
| 1 | Vendor CSAF 2.0 / VEX, or a vendor per-CVE API | Microsoft (SUG API, as used here), Red Hat, SUSE, Cisco, Siemens and the other CSAF publishers | **Do not maintain a hand list.** CSAF has a discovery mechanism: `https://<vendor>/.well-known/csaf/provider-metadata.json`, and the CSAF aggregators (e.g. BSI's `wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json`) enumerate publishers. Resolve per vendor at run time and cache. |
| 2 | The CNA's own CVE record (CVE JSON 5.x from cvelistV5) — **its `configurations` and `workarounds` containers**, when present | **every CVE** has the record; the containers are filled in **1.2% / 2.7%** of KEV records (`STANDARDS.md`, measured 2026-09-02) — Palo Alto 71%, most CNAs 0% | When filled they are the best text there is (they name gates the description never mentions — see the Palo Alto comparison in `STANDARDS.md`). When empty, the record's `descriptions` field *is* what NVD republishes, so rung 2 collapses into rung 4. Always check the containers; never assume them. |
| 3 | The vendor advisory page referenced from the CVE record (`references[]` tagged `vendor-advisory`) | most of the rest | Fetch, strip HTML (the `fetch_msrc.py` stripper generalises), store the text with a content hash. Fragile to page changes, which is why `retrieved` + hash are mandatory: a citation is re-checkable only against the text as captured. |
| 4 | NVD description | everyone | The floor, not the default. |
| — | GHSA body | open-source ecosystems | For OSS, the GHSA body is usually the richest citable text and is already a `source` value. |

**What makes it validated rather than hopeful — three mechanisms, all already in this
directory or the schema:**

1. **Provenance on every record** — `source`, `source_url`, `retrieved`, and (add) a `sha256`
   of the captured text. Any `cites` is re-checkable forever against what the model actually
   saw, regardless of what the vendor page says today.
2. **The mechanical check at ingest** — `schema.py` rejects a `cites` that is not a substring
   of `advisory_text` (whitespace and NBSP normalised). A record that fails is not stored; a
   model cannot smuggle in a precondition the text does not carry.
3. **The empty-rate as the coverage signal** — run a vendor at the rung you have; the share of
   records reading *"this text states no precondition"* is the measurement. Microsoft at rung 4
   read 80% empty; at rung 1, 27%. A vendor with a high empty-rate at rung 2 is promoted to rung
   3 and re-measured. Vendors are promoted by data, never by assumption, and the per-vendor
   empty-rate is itself publishable — it says which vendors' advisories carry applicability
   information at all.

**Two honest limits.** A vendor with no citable text anywhere gets an honest empty record and
the ledger shows *"no gate text available"*, not a guess. And the 50-record set is the
regression gate for every source or model change: re-run `compare.py` before trusting a new
rung, exactly as was done for Haiku, Sonnet and Rule 8.

**Order of work for the KEV catalogue (~1,700 CVEs), corrected after measuring:** fetch the CNA
record for everyone (one feed) and use `configurations` + `workarounds` where filled (~1–3%);
for the rest, rung 1 where a CSAF/per-CVE source exists (Microsoft SUG proven; check
`.well-known/csaf` per vendor); then rung 3 — the vendor advisory page the CNA record links to —
for the vendors whose empty-rate stays high, which the scan says is most of them. Rung 3 is
where the bulk of the work is; plan for it rather than around it. See `STANDARDS.md` for the
numbers and for where cited preconditions fit SSVC, VEX and the CVE record format.

### Fifth run, 2026-09-02 — Sonnet 5, blind, Rules 8–10: **passes**

The owner accepted Rules 9 (user interaction) and 10 (component in use); both are in
`PROMPT.md` and the skill. Same blind protocol as the fourth run (reference, candidates, this
README, `STANDARDS.md`, comparisons and scorer moved out of the tree; five of five transcripts
clean). Output in `candidates/sonnet-r10/`; scoring in `compare-sonnet-r10.md`.

| scope | ref #pre | Sonnet-R10 #pre | cite_valid | recall (exact) | recall (containment) | precision | empty_agree | text drift |
|---|---|---|---|---|---|---|---|---|
| **all** | 72 | 72 | **1.00** | **0.90** | **0.92** | **0.93** | **0.94** | 1* |
| edge | 31 | 37 | 1.00 | **0.96** | 0.97 | 0.95 | 1.00 | 1* |
| microsoft | 13 | 11 | 1.00 | 0.69 | 0.69 | 0.82 | 0.80 | 0 |
| oss | 28 | 24 | 1.00 | **0.95** | 0.96 | 0.96 | 1.00 | 0 |

\* CVE-2026-20349: the model normalised the Cisco text's CRLF line endings; no wording changed.

**The scorer's citation check now normalises whitespace and NBSP** (`compare.py`, same rule as
`schema.citation_in_text`); re-scored under that rule every prior run also reads cite_valid
1.00 — the earlier 0.91–0.94 figures were the byte-strict artefact noted in the fourth run, not
model errors. Haiku's six altered-text records remain real.

**Progression, blind, same 50 CVEs, same model where applicable:**

| run | rules | recall (exact) | precision | empty_agree | verdict |
|---|---|---|---|---|---|
| Haiku 4.5 | 1–7 | 0.42 | 0.56 | 0.78 | fail |
| Sonnet 5 | 1–7 | 0.60 | 0.90 | 0.80 | fail |
| Sonnet 5 | 1–8 | 0.75 | 0.98 | 0.84 | fail (edge passes) |
| **Sonnet 5** | **1–10** | **0.90** | **0.93** | **0.94** | **pass** |

Every step up came from a rule, not a model. The standard was under-specified in three named
places; naming them moved recall from 0.60 to 0.90 on the same model.

**What is left, and why it is now the reference's turn.** Six reference gates are still missed
and five candidate gates have no reference counterpart. Reading them side by side, most of the
"extras" are *correct under Rules 8–10* and the reference — written before those rules — is
what is behind: CVE-2016-0165's "local users … via a crafted application" is a Rule 8 + Rule 9
gate the reference left empty; CVE-2025-20352's "SNMP subsystem enabled" is a Rule 10 gate the
reference folded into reachability; CVE-2022-0995's watch_queue presence likewise. The six
misses are single-record judgement calls (Exchange reachability *and* authentication vs
authentication alone; Preview Pane as a second gate; Grafana Cloud exclusion). **Next step:
re-verify the 50 reference records under the ten rules**, then re-score — expected effect is
precision rising toward recall, not recall changing.

### Sixth pass — the reference re-verified under the ten rules (2026-09-02)

Done. **The prediction in the paragraph above was wrong**, and it is left standing there
unedited because a conformance set whose owner quietly revises its own predictions is worth
nothing. Recall did change: it **fell for every run**. Correcting the reference added 16
preconditions (72 → 88) and the models had not found most of those either, so the denominator
grew faster than the credit did.

26 of the 50 records changed. Three systematic classes, none of them one-offs:

| class | n | why it existed |
|---|---|---|
| Rule 8 — "attacker must hold" gate filed as `network-reachability` | 6 | no category for it before Rule 8 |
| Rule 9 — "victim must open artefact" gate filed as `network-reachability` | 6 | same gap, before Rule 9 |
| Rule 10 — named optional component's presence not recorded at all | 12 | no Rule 10 |
| empty record that should not have been (CVE-2016-0165) | 1 | judgement call Rule 8 reverses |
| `attacker-controlled-log-input` api-usage → deployment (CVE-2021-44228) | 1 | drift between SKILL.md and the fixture |

**Re-scored against the corrected reference:**

| run | rules | recall | precision | empty_agree | cat_agree | verdict |
|---|---|---|---|---|---|---|
| Haiku 4.5 | 1–7 | 0.42 → **0.37** | 0.56 → 0.56 | 0.78 → 0.80 | 0.40 → 0.40 | fail |
| Sonnet 5 | 1–7 | 0.60 → **0.54** | 0.90 → 0.90 | 0.80 → 0.78 | 0.58 → 0.56 | fail |
| Sonnet 5 | 1–8 | 0.75 → **0.67** | 0.98 → 0.98 | 0.84 → 0.86 | 0.64 → 0.67 | fail |
| **Sonnet 5** | **1–10** | 0.90 → **0.84** | 0.93 → **0.97** | 0.94 → **0.96** | 0.46 → **0.66** | **pass** |

The gating run still clears every threshold (cite_valid 1.00 ≥ 0.95, recall 0.84 ≥ 0.80,
empty_agree 0.96 ≥ 0.90) — but with **0.04 of headroom, not 0.10**. The claim "Sonnet under the
ten rules passes" survives; the claim that it passes comfortably does not.

**`cat_agree` 0.46 → 0.66 is the finding.** Category agreement rose by 20 points without the
model changing at all, which is what it looks like when the *reference* was the thing at fault:
the model had been filing gates in categories the corrected reference now agrees with, and was
being marked down for it.

**Per-scope, the weakness is now located rather than suspected:**

| scope | recall | precision | empty_agree |
|---|---|---|---|
| edge | 0.97 | 0.97 | 1.00 |
| oss | 0.90 | 1.00 | 1.00 |
| **microsoft** | **0.53** | 0.90 | 0.87 |

MSRC FAQ prose is where the method is weakest — and since the edge stratum is what the controls
ledger is actually built on, that is the least damaging place for it to be weak. It does mean
"re-source Microsoft from MSRC" fixed the *empty-rate* (80% → 27%) without fixing recall.

**Method.** Seven readers took a batch each, each seeing only the rules and its own records —
never `candidates/`. A mechanical sweep (`sweep_categories.py`) then enumerated classes A/B/D
over all 50, because a record-by-record review is exactly the shape of review that lets a
systematic defect survive in the batch nobody read with the class in mind. The sweep was
verified non-vacuous against the pre-fix records: **6 class-A and 6 class-B hits at HEAD, 0
after**. Every one of those 12 had been independently reported by the reader holding that batch,
so the mechanical and human passes agree exactly — which is the only reason to believe either.

Three clarifications were settled and written into Rule 10 so the next pass does not re-decide
them: one gate per component (not presence *and* enable-state); "present" and "reachable" *are*
two gates when independently falsifiable; and only genuinely optional components count — a core
OS component or the record's own `identity.product` gets no presence gate, because a gate that
can never be false is the product name restated.

Two scorer defects were found in the process and fixed. `compare.py` printed a complete,
clean-looking table of zeros for a mistyped `--cand`, because `Path.glob` on a missing directory
yields nothing rather than raising — a comparison that never ran, reported as one that found
nothing wrong. And a test hardcoded the precondition total `72`, a number that legitimately
moves whenever a rule is adopted.

**Verdict.** Sonnet 5 under the ten-rule standard passes the gate on the whole sample, and by a
wide margin on the edge and open-source strata the controls ledger is built on. Microsoft
remains the weakest stratum (0.69) for the reason the source finding gives: 13 reference gates
across 15 CVEs, four of them empty by source; each single miss moves the number by 8 points.
Production extraction can proceed on Sonnet 5 under a Claude Max subscription with no API key.

### Seventh pass — held out, and what it does not prove (2026-09-03)

**Read this first.** Every number above is a *training* score. Rules 8–10 were adopted because
of failures on these 50 records, and the reference was then rewritten to match them. This pass
draws 30 KEV CVEs the rules were never tuned on, freezes the rules against them
(`heldout/RULES_FROZEN.json` pins `sha256(PROMPT.md)`; `tests/test_heldout.py` fails if it
moves), and scores once.

**And the caveat that governs everything below: there is still no human annotator.** The
reference was built blind by five Opus agents; the candidate is Sonnet. Both are Claude models,
so their errors are likely *correlated*, and every agreement figure here is an **upper bound**,
not an unbiased estimate. The owner's 15-record blind annotation — the human ceiling — was
attempted and parked (`heldout/owner/`, and *How to finish this* below). Until it exists we do
not know whether these numbers are good. If two experts agree at 0.75, a model at 0.89 is above
the human ceiling and means something entirely different from what it looks like.

**The draw.** 12 edge / 9 Microsoft / 9 OSS, same stratification as the 50, drawn from
`pipeline/data/inputs.json` with the 50 development IDs and the 170 `edge-2023plus` IDs
excluded (`heldout/draw.py`). One consequence to carry: the 170-CVE run consumed the recent
edge population, so **the held-out edge stratum is entirely pre-2023** — held-out edge against
the reference's edge stratum is not like-for-like.

**Ordering, corrected.** The plan said the owner annotates first, then Claude. Wrong: the real
constraint is *mutual* blindness, not sequence. The build ran while the owner's 15 worksheets
were verifiably empty (checked and recorded before launch), which makes contamination
structurally impossible rather than a rule someone has to keep.

#### The scorer was wrong, and the held-out set is what exposed it

`compare.py` keyed on exact normalised sentence equality. On CVE-2016-8735 both annotators found
the *same two gates* — the reference quoted the whole enclosing sentence for both, the candidate
quoted the two precise clauses ("JmxRemoteLifecycleListener is used", "an attacker can reach JMX
ports"). Exact overlap: **zero**. The candidate was arguably citing better.

So `compare.py` now reports exact **and** containment, and neither alone is the answer: exact is
a lower bound (it punishes span choice), containment an upper bound (a long sentence can swallow
an unrelated clause). Auditing all 33 containment matches, only **2** are credited solely by a
gate in a different category, so the defensible figure is category-consistent containment.

| | dev set (50) | held out (30) |
|---|---|---|
| recall, exact span | 0.84 | **0.60** [0.44, 0.74] |
| recall, containment | 0.85 | **0.94** [0.81, 0.98] |
| **gap** | **1 pt** | **34 pt** |

**That gap is the tuning signature.** On the development set exact ≈ containment because the
reference was iterated against the candidates until they converged on the same spans. On unseen
records, where nothing converged, exact collapses and containment holds. The old 0.84 was
measuring span convergence as much as gate agreement.

#### The held-out numbers

29 of 30 scored (one rejection, below). Wilson 95% intervals throughout.

| metric | value | 95% CI |
|---|---|---|
| **cite_valid** | **1.00** (43/43) | [0.92, 1.00] |
| **empty_agree** | **1.00** (29/29) | [0.88, 1.00] |
| recall, category-consistent containment | **0.89** (31/35) | [0.74, 0.95] |
| recall, containment | 0.94 (33/35) | [0.81, 0.98] |
| recall, exact span | 0.60 (21/35) | [0.44, 0.74] |
| Cohen's kappa (span level) | **0.926** | "almost perfect" |
| category agreement | 0.92 (36/39) | |

Per stratum, exact / containment: edge 0.72 / 0.94, Microsoft 0.83 / 1.00, OSS 0.27 / 0.91.
**Microsoft is the best stratum here and was the worst on the dev set (0.53)** — but it is 6
gates with a CI of [0.44, 0.97], so that reversal is not a finding, it is noise. OSS has the
widest exact/containment gap because its annotators quoted whole sentences.

`compare.py`'s verdict line still reads NOT ACCEPTABLE, because it tests exact recall against a
0.80 threshold calibrated on a set where exact ≈ containment. **The threshold is now measuring
something different from what it was set for.** It is left failing rather than quietly
re-pointed at containment — moving a threshold to pass is the exact failure this pass exists to
catch. Re-deriving thresholds against the containment key is the next rule-set decision, and it
needs its own draw.

#### The one rejection

CVE-2022-41328: the model emitted `"…via crafted CLI commands via crafted CLI commands"` — a
duplicated clause, so the citation was not a substring and the whole record was rejected. Its
*reading* was right (both gates match the reference); the transcription was malformed. That is
**3.3% record loss to a splice error**, and it is the cost of rejecting per record rather than
per precondition. The rule was not relaxed mid-experiment; whether it should be is a real
question now that the cost is measured.

#### What this pass does and does not establish

**Does:** the citation discipline holds on unseen data — 43 of 43 citations valid, and the two
empty readings agreed on 29 of 29 records. Gate-finding agreement between two independent
annotators is 0.89 [0.74, 0.95], kappa 0.93. Neither number was available before, and neither
was tuned.

**Does not:** that a *human* would agree. Both annotators are Claude models. Nor that the gates
are *true of real deployments* — construct validity is still untested, and no extracted gate has
ever been checked against a live system.

#### How to finish this

`heldout/owner/` holds 15 blank worksheets: the advisory as numbered sentences, and a table
wanting a sentence number, a category, a one-line statement and y/n/?. Picking the number *is*
the citation. `worksheet.py --collect` turns filled sheets into records; `agreement.py --a
heldout/annotators/owner --b heldout/annotators/claude --disagreements` produces the kappa and
the adjudication list.

**The contamination rule:** whoever helps must not have seen `heldout/annotators/claude/`. Any
assistant that has read the batch results is compromised as an adviser and can act only as a
transcriber, never as a judge of whether an answer is right.
