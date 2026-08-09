# Routing registry — analyst guide

A plain-English guide for the analysts who work the queue. No CLI experience
assumed: every command here can be run by you *or* handed to whoever operates
the registry — the decisions are yours either way; only the typing is optional.

## 1. Why this exists

In July 2026, 9,919 CVEs were published in one month. The cohort exercise
behind this registry showed the real shape of that problem: **21%** screened
instantly, **57%** collapsed into just ten channel records, and **22%** were
unroutable — the part that genuinely needs analyst judgement. Every judgement
you make on the unroutable queue becomes a rule, so next month's queue is
smaller. One metric tells you it's working:

> **`unroutable_pct`, run over run.** Falling = the registry is learning.
> Plateaued = the queue isn't being converted into rules.

## 2. The pipeline: four gates, first match wins

Every finding passes through the same stages in order; the first rule that
fully matches decides it.

1. **Screens** — "should this exist here at all?" Rejected CVEs,
   out-of-program software, bulk-feed noise. `drop` discards with a recorded
   reason; `park` sends to a named review queue.
2. **Corrections** — "have we learned better for this deployment?" Learned
   overrides that fire only when deployment context is present. Most
   specific, so they go first.
3. **Identity** — "what software is this?" Vendor, CNA, package URL,
   keywords → default channel.
4. **Unroutable** — no rule matched. Your adjudication queue. Every item
   here should end its life as a new rule, never as a repeated manual
   decision.

## 3. The two questions: identity vs. context

- **Identity** — *what software is this?* True everywhere. An Oracle CVE
  belongs to Oracle's quarterly CPU no matter who you are.
- **Context** — *how is this instance deployed here?* True only for a
  specific deployment in your estate.

The seed data proves it with one Tomcat CVE and three routes:

| Deployment context | Routed to | Stage |
|---|---|---|
| `image_layer: base` (golden base image) | `platform-rehydrate` | correction |
| `image_layer: app` (app's own Dockerfile) | `build-dependency` | correction |
| no context data | `middleware` | identity |

**Corrections are safe by default**: a context rule fires only when the
context key is actually present on the finding. No deployment data → no
override → the identity default holds.

## 4. Reading a routing result

Each finding comes back with a **disposition**, the **channel** (if routed),
and the exact **rule that decided it**.

| Disposition | Meaning | What you do |
|---|---|---|
| `routed` | In a channel with a delivery rhythm | Usually nothing. Watch for findings that *survive* their channel's cycle — that's a misroute signal. |
| `screened` | Removed before routing (dropped with a reason, or parked in a queue) | Nothing for drops; parked queues get a periodic sweep. |
| `unroutable` | No rule matched | **Your job.** Decide the right home once, then turn it into a rule. |

## 5. Your working loop

1. **Route the batch** (CSV or JSONL in, one decision per line out):

   ```bash
   python -m routing_registry route --registry registry --findings batch.jsonl --stats
   python -m routing_registry route --registry registry --findings batch.jsonl --unroutable-only
   ```

2. **Work the unroutable queue, biggest groups first.** Group by
   vendor/product, take the biggest group, decide its home **once**. The
   question is always: *which delivery mechanism will actually ship this
   fix?* If no channel fits, that's a conversation about adding a channel.

3. **Spot misroutes among the routed.** Three signals, in order of value:
   - **Survived the cycle** — routed to a scheduled channel, still open
     after the cycle ran.
   - **Reassigned ticket** — a human moved it; they just told you the route
     was wrong.
   - **Closure mismatch** — closed "remediated by cycle X" but the next
     scan still sees it.

4. **Turn the decision into a rule** (next section).

## 6. Requesting a correction — the fill-in form

A correction needs seven pieces of information. If you can fill this in,
you've done the analyst work; the command is the form re-typed.

| Field | What to write |
|---|---|
| Where it should go | Channel id, e.g. `euc-user-installed` |
| What it matches | Vendor and/or keywords, e.g. vendor `microsoft`, keyword `visual studio` |
| Deployment condition | The context fact making this deployment different — **required**. Wrong for *every* instance? Then it's an identity-rule fix instead. |
| Who decided | Your name — goes into the permanent provenance record |
| Why (trigger) | One sentence a stranger understands next year |
| Evidence | Ticket / scan reference (optional but valuable) |
| Re-check date | When to re-verify — **always set for volatile facts** like bundle membership |

As the command:

```bash
python -m routing_registry propose-correction --registry registry \
    --route euc-user-installed \
    --match vendor=microsoft --match "keywords=visual studio" \
    --context bundle_member=false \
    --decided-by your-name \
    --trigger "survived 2 central patch cycles" \
    --review-by 2027-02-01 \
    --fixture-finding the-finding.json
```

It validates the whole registry before accepting (rolls back if anything
breaks), then appends the rule **and** freezes the triggering finding as a
regression test. What lands in git is a small readable diff for someone to
approve — that approval *is* the review process.

## 7. Which file does what

| I want to… | Edit | Watch out for |
|---|---|---|
| Add/split a delivery channel | `registry/channels.yaml` | A channel is a delivery mechanism with a rhythm — not a team. |
| Stop a class of noise | `registry/screens.yaml` | Keep screens coarse; a screen needing deployment context is a correction in the wrong file. |
| Route a software identity | `registry/rules/identity.yaml` | Lower `priority` wins; check what your rule shadows. |
| Record a deployment override | `registry/rules/corrections.yaml` | **Append-only — use the command, never hand-edit.** |

## 8. Golden rules

1. **Corrections are append-only.** Supersede, never rewrite. The file plus
   git history is the audit trail.
2. **Every unroutable finding should die as a rule.** Adjudicating the same
   product twice means the first adjudication was wasted.
3. **Volatile facts carry a re-check date.** Bundle membership goes stale
   first; the monthly hygiene sweep clears flagged rules in one sitting.
4. **Right file for the job.** Wrong everywhere → identity. Wrong for this
   deployment → correction (the tooling refuses a correction without a
   context predicate).
5. **Validate after every change; CI is the safety net.**
   `python -m routing_registry validate --registry registry` plus the
   regression fixtures — nothing merges if it breaks a past decision.

## 9. Channel glossary

See `registry/channels.yaml` for the full descriptions. Cadence types:
**scheduled** (fixed rhythm you can wait for), **continuous** (rolling —
ride the lane, escalate survivors), **ad hoc** (no cycle is coming).

| Channel | Covers | Cadence |
|---|---|---|
| `windows-os` | Windows OS via monthly cumulative update | scheduled |
| `euc-central-bundle` | End-user software in the central monthly push | scheduled |
| `euc-user-installed` | Endpoint software *not* in the bundle | ad hoc |
| `mac-endpoint` | macOS via MDM | ad hoc |
| `linux-os` | Distro packages + kernel on managed hosts | continuous |
| `oracle-cpu` | Everything on Oracle's quarterly CPU | scheduled |
| `build-dependency` | App dependencies via CI version bumps | continuous |
| `platform-rehydrate` | Software baked into golden images | scheduled |
| `middleware` | Host-installed app/web servers, brokers | ad hoc |
| `network` | Network device firmware/OS | ad hoc |
| `virtualisation` | Hypervisors and virtualisation platforms | ad hoc |
| `vendor-product` | Named enterprise products with own patch programme | ad hoc |
| `cloud-managed` | Provider-patched managed services | continuous |

Companion docs: [sql-powerbi.md](sql-powerbi.md) (running these rules in the
in-house database that feeds Power BI), [ownership-and-sources.md](ownership-and-sources.md)
(Qualys/Wiz/GitHub sources, central vs distributed ownership, legacy risk
bundles), [tutorial.md](tutorial.md), [schema-reference.md](schema-reference.md).
