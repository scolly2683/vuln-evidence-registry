# Translating the routing registry into your organisation

The module is deliberately liftable: copy the `routing-registry/` folder into
a **private** config repo and the engine comes with it (stdlib + PyYAML, no
service dependencies). What changes is the data. This guide is the ordered
checklist for that translation. Nothing here names an employer or a specific
product estate — map the generic names onto whatever you run.

## 1. Split public engine from private facts

Keep two layers with different sharing rules:

| Layer | Contents | Where it lives |
|---|---|---|
| Engine + schema | `routing_registry/`, file formats, CLI, tests | public / shared |
| Learned facts | your channels, owners, bundle membership, base-image digests, screens | private repo, access-controlled |

The learned facts are an inventory of how your estate ships fixes — treat the
private registry with the same sensitivity as a CMDB export.

## 2. Rewrite the channel list as *your* delivery mechanisms

Walk each seeded channel and ask: does a mechanism with this rhythm exist
here, and what is it actually called? Typical mappings:

- `windows-os` / `euc-central-bundle` → your endpoint-management monthly push
  (SCCM/Intune-class tooling). **Write down what is actually in the bundle** —
  the packaging team has a manifest; that manifest is the ground truth the
  `bundle_member` context predicate needs.
- `linux-os` → your managed-host patch cycle. Adopt the patch-cycle-lane
  discipline: route and record, assign nobody, escalate what survives.
- `platform-rehydrate` → your golden-image rebuild process. The enabler is a
  **base-image digest table** (layer digest → owning platform team): any
  image sharing a digest below the waterline auto-attributes to the platform
  channel regardless of what the final tag is called.
- `build-dependency` → your Renovate/Dependabot lane. Its boundary is the
  pipeline: apps outside CI/CD will surface as corrections routing *out* of
  this channel — that's the loop working, not a failure.
- `oracle-cpu`, `vendor-product`, `network`, `virtualisation`, `mac-endpoint`,
  `cloud-managed` → keep, rename, or split per your estate. Split a vendor
  into its own channel when volume or cadence justifies it.

Then fill `owner:` on every channel. This is the tractable version of the
ownership problem: a dozen names, not ten thousand per-finding decisions.

## 3. Wire context enrichers

Corrections are only as good as the context on the finding. Enrich findings
before routing, from sources you already have:

| Context key | Source of truth |
|---|---|
| `bundle_member` | endpoint packaging team's bundle manifest (export it; re-export on every bundle change) |
| `image_layer` (`base`/`app`) | registry scanner layer attribution, or the base-image digest table |
| `managed` | endpoint management enrolment status |
| `os_family` | inventory / MDM |
| `in_pipeline` | CI/CD coverage list (which repos Renovate actually watches) |
| `internet_facing` | EASM / CMDB exposure flag (also feeds your SLA clock, e.g. BOD-26-04-style 3-day criteria) |

Resolution precedence when sources disagree: **runtime > artifact/registry >
source/manifest** — the layer closest to what is actually executing wins.

## 4. Point the misroute detectors at your ticket system

The loop needs a signal that routing was wrong. Three queries, in order of
value:

1. **Survived-cycle query**: findings routed to a scheduled channel, still
   open after that channel's cycle ran. (Needs channel cadence + finding
   age — both already in the registry/finding data.)
2. **Reassignment query**: tickets whose assignment group changed after
   creation — each is a human telling you the route was wrong.
3. **Closure-mismatch query**: tickets closed "remediated by <cycle>" where
   the scanner still detects the finding next scan.

Route each hit through `propose-correction` with the ticket as `--evidence`.
Start manual (weekly triage agenda item); automate the queries once the
correction format is stable.

## 5. Governance

- Corrections merge by pull request; the registry directory gets a
  CODEOWNERS entry so the routing owner reviews every rule change.
- CI runs `validate` + the regression fixtures on every change (workflow
  ships in this repo — reuse it).
- Monthly hygiene sweep: `validate` output lists rules past `review_by`;
  re-verify or retire them in one sitting. Bundle-membership rules are the
  ones that go stale first.
- Never edit a shipped correction in place: supersede it with a new entry.
  The append-only file plus git history is your audit trail — the same
  discipline as an immutable audit log, implemented socially rather than in
  a database.

## 6. Metrics that prove it's working

- **`unroutable_pct` per run** — the convergence curve. This is the number
  that justifies the tool's existence; chart it from run one.
- Corrections proposed vs merged per month (loop throughput).
- Survived-cycle count per channel (misroute pressure — a channel with many
  survivors has a wrong boundary or a broken cycle).
- Rules past `review_by` (hygiene debt).

## Rollout order that worked on paper

1. Seed channels + owners (one workshop with the packaging/platform teams).
2. Run read-only against one month of findings; eyeball the routes.
3. Adjudicate the unroutable queue top-down by volume; every decision → rule.
4. Turn on the survived-cycle query; corrections start flowing.
5. Only then let routing drive ticket assignment.
