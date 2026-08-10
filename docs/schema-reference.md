# Schema reference

Complete field reference for the four registry files, the finding input
format, and the exact matching semantics. The loader (`loader.py`) enforces
everything marked **required**; soft rules surface as `validate` warnings.

## Registry layout

```
registry/
  channels.yaml            # list of channels
  screens.yaml             # list of screen rules
  rules/
    identity.yaml          # list of identity rules
    corrections.yaml       # APPEND-ONLY list of correction rules
fixtures/
  regression.yaml          # list of routing test cases (lives beside registry/)
```

All files are **top-level YAML lists** — a deliberate choice so corrections
and fixtures can be appended without rewriting the file (preserving comments,
diffs, and `git blame`).

## Channel

```yaml
- id: oracle-cpu                  # required, unique
  name: Oracle CPU                # display name (defaults to id)
  description: >-                 # what this delivery mechanism is
    Everything fixed via Oracle's quarterly Critical Patch Update.
  cadence: "Quarterly — third Tuesday of Jan/Apr/Jul/Oct"   # human-readable rhythm
  cadence_type: scheduled         # scheduled | continuous | ad_hoc
  owner: UNASSIGNED               # fill in your org's owning team
  parent: null                    # optional parent channel id (must exist)
```

A channel is a **delivery mechanism with a rhythm**, never a team. `owner`
is metadata for your org to fill; the engine doesn't act on it.

## Rule (all kinds)

| Field | screen | identity | correction | Notes |
|---|---|---|---|---|
| `id` | required | required | required | unique across ALL rule files |
| `match` | subject predicates | subject predicates | subject predicates | see Matching semantics |
| `context` | optional | optional (rare) | **expected** (loader warns if absent) | see Context predicates |
| `route` | — | required, known channel | required, known channel | |
| `action` | required: `drop` \| `park` | — | — | |
| `queue` | required when `park` | — | — | named review queue |
| `priority` | default 100 | default 100 | default 100 | lower fires first, ties broken by id |
| `provenance` | optional | optional | **required** `{date, decided_by, trigger}` + optional `evidence` | |
| `review_by` | optional | optional | recommended for volatile facts | ISO date; past date ⇒ warning, rule stays active |
| `note` | optional | optional | optional | free text for the next reader |

## Matching semantics (`match:` block)

All predicates in a block must hold (AND). Within one predicate, any listed
value may hold (OR). Unknown keys are a **validation error** — typos fail
loudly instead of silently never matching.

| Key | Matches against | Semantics |
|---|---|---|
| `cna` | finding `cna` | case-insensitive; equal **or contained in** the finding value |
| `vendor` | finding `vendor` | same — `"red hat"` matches `"Red Hat, Inc."` |
| `product` | finding `product` | same |
| `package` | finding `package` | same |
| `source` | finding `source` | same |
| `nvd_status` | finding `nvd_status` | same |
| `purl_prefix` | finding `purl` | case-insensitive `startswith`; use canonical [purl types](https://github.com/package-url/purl-spec) (`pkg:golang/`, not `pkg:go/`) |
| `keywords` | `product` + `package` + `description` concatenated | case-insensitive substring, any keyword |

An **empty finding field never matches** — a rule requiring `vendor` cannot
fire on a finding with no vendor.

An **empty `match:` block matches everything.** Legitimate only on a screen
paired with a context predicate; on identity rules it is a design smell.

## Context predicates (`context:` block)

Evaluated against the finding's `context` object.

```yaml
context:
  bundle_member: false            # scalar → equality
  image_layer: base               # scalar → equality
  os_family: {in: [macos, ios]}   # membership
  managed: {not: true}            # negated equality
```

**The key must be PRESENT on the finding.** Absent context never satisfies
any predicate — including `not`. This is the engine's core safety property:
a correction can only override the identity default for findings whose
deployment context is actually known. No data, no override.

## Finding input

JSONL (one object per line) or CSV (flat columns, no context). All fields
optional — the more you supply, the more rules can fire.

```json
{
  "id": "f-123",                     // your finding/ticket id
  "cve_id": "CVE-2026-12345",
  "cna": "kernel.org",               // assigning CNA — strongest early signal
  "vendor": "Apache",
  "product": "Apache Tomcat",
  "package": "tomcat-embed-core",
  "purl": "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.0",
  "description": "Request smuggling in HTTP/2 handling.",
  "nvd_status": "Awaiting Analysis",
  "source": "scanner-name",
  "context": {                       // deployment facts from your enrichers
    "image_layer": "app",            // base | app
    "bundle_member": false,
    "managed": true,
    "os_family": "linux",
    "in_pipeline": true,
    "internet_facing": false
  }
}
```

Context keys are **an open namespace** — the engine imposes none. The six
above are the conventions the seed rules and docs use; add your own and
reference them from corrections.

## Route result (output, one JSON line per finding)

```json
{"finding_id": "f-123", "cve_id": "CVE-2026-12345",
 "disposition": "routed",        // screened | routed | unroutable
 "channel": "build-dependency",  // null unless routed
 "rule_id": "corr-20260809-tomcat-app-layer",  // which rule fired
 "stage": "correction",          // screen | correction | identity
 "queue": null}                  // park queue when screened+parked
```

## Regression fixture

```yaml
- name: corr-20260809-tomcat-app-layer   # convention: the correction's rule id
  finding: { ...exact finding object... }
  expect:
    disposition: routed          # required
    channel: build-dependency    # optional but recommended
    rule_id: corr-20260809-tomcat-app-layer   # optional: pin WHICH rule fires
```

`propose-correction --fixture-finding` writes one automatically. The test
suite parametrizes over every fixture; keep them forever.

## Evaluation order (normative)

1. **screens** — by `(priority, id)`; first match screens the finding
   (`drop` discards, `park` sends to `queue`).
2. **corrections** — by `(priority, id)`; first full match routes.
3. **identity** — by `(priority, id)`; first full match routes.
4. otherwise **unroutable** — the adjudication queue.

Deterministic, no scoring, no fallthrough-with-weights. If two rules can
both claim a finding, the outcome is decided by kind then priority then id —
and a regression fixture is how you make that decision permanent.
