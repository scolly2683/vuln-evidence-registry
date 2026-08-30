# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Who you're working with

The repo owner is a **vulnerability management practitioner, not a software engineer**. They
understand CVEs, KEV, EPSS, SSVC, patch cadences, and how a VM program actually runs day to day —
but they have **no coding background**. This changes how you should operate here, always:

- **Explain plainly, one step at a time.** Don't dump a wall of code or a multi-step plan and
  expect them to follow it. Say what you're about to do, in plain English, before you do it. After
  a change, say what changed and why, without jargon (or with jargon defined inline the first time
  you use it — e.g. "a *predicate* — just a yes/no check").
- **Don't assume familiarity with dev tooling.** Terms like "pytest", "git diff", "YAML", "CLI",
  "stdlib" are not obvious to this user. When you need to use them, gloss them briefly ("`pytest`
  — the tool that runs the automated tests").
- **Prefer small, reversible, checked-in steps over big rewrites.** Make one change, explain it,
  show that the tests still pass, then move to the next thing. Don't silently batch five unrelated
  changes into one commit.
- **When something requires a judgment call about VM process** (e.g. how a fix channel should be
  owned, what counts as a legitimate suppression), treat the user as the domain expert and ask —
  they know the practitioner side better than you do. When something is a coding/design judgment
  call, make the call yourself and explain the reasoning simply.
- **Never assume prior exposure to this codebase's internals.** Re-orient briefly rather than
  referencing file/function names as if they're already familiar.

## What this project is

`vuln-evidence-registry` is a set of small, working **vulnerability-prioritisation and routing
patterns**, extracted from a real CVE intelligence pipeline. It is not a full vulnerability
management platform (no dashboard, no ticketing, no scanner integration UI) — it's the
**decision logic** a VM program needs, built as tested, reusable code plus documentation on how to
adopt it. Think of it as "the brain," meant to sit behind whatever "body" (ServiceNow VR,
DefectDojo, a bought platform, etc.) actually executes tickets and dashboards. See `STATUS.md` for
an honest ledger of what's real, working code (covered by tests) versus what's design/documentation
only.

There are three patterns, all under one MIT-licensed repo:

### Pattern 1 — The evidence-source registry (`vuln_evidence_registry/evidence_sources.py`)

**Problem it solves:** VM teams often decide "is this CVE high-priority?" twice — once by hand as
a SQL query (to filter a whole database) and once by hand as application logic (to check one
record). The two get written separately, and they drift apart over time as people forget to update
one when they update the other.

**The fix:** one list of evidence sources (KEV, EPSS score threshold, SSVC decision points, etc.)
that gets *turned into* both a SQL query and a Python check automatically, so there's only ever one
place to add a new evidence source and both outputs stay in sync by construction.

### Pattern 2 — BOD 26-04 remediation timeline engine (`vuln_evidence_registry/bod_26_04.py`)

**Problem it solves:** CISA's BOD 26-04 directive sets remediation deadlines based on four
yes/no factors (publicly exposed? in KEV? automatable? total technical impact?). Hand-coding that
logic invites mistakes, especially edge cases like "an exposed KEV entry is always the strict
3-or-14-day deadline, never the looser one."

**The fix:** the directive's decision table is encoded directly as code, with tests that pin down
the tricky edge cases so a future change can't accidentally loosen a deadline it shouldn't.

### Pattern 3 — The learning routing registry (`routing_registry/`, `registry/`)

**Problem it solves:** most CVEs shouldn't go to an analyst at all — they should route straight to
an existing fix mechanism (Patch Tuesday, a distro's security updates, a dependency bump, etc.).
Deciding that routing by hand for every finding doesn't scale, and mistakes ("we routed this to the
wrong team") need to be correctable without losing the history of *why* the correction was made.

**The fix:** a registry of routing rules, stored as YAML files under `registry/`, that:
- decides where each finding should go along **two axes** — *what software is this* (identity) and
  *how is it deployed here* (context, e.g. is it in a container base image or an app team's repo);
- lets you **append corrections** (with mandatory notes on who decided it and why) when routing
  turns out to be wrong, rather than editing the original rule and losing that history;
- turns every corrected finding into a **permanent regression test fixture**, so a future rule
  change can never silently re-break something that was already fixed.

Docs for pattern 3 live in `docs/` (start with `docs/routing-registry.md` and `docs/tutorial.md` —
the tutorial is written to be walked through in about 15 minutes).

## Working in this repo

- Tests live in `tests/` and run with `pytest -q` (in plain terms: this runs every automated check
  in the repo and tells you pass/fail — always run this after making a change, and explain the
  result to the user in plain language, e.g. "all 40 checks still pass" or "this one check broke,
  here's why").
- `python -m routing_registry validate --registry registry` checks that the routing YAML files
  (`registry/channels.yaml`, `registry/screens.yaml`, `registry/rules/`) are internally consistent.
- Prefer editing the registry/rule data (YAML) over changing code when the task is "add a new
  source/channel/rule" — that's the whole point of these being registries.
- Follow this repo's general engineering norms too: no unrequested refactors, no speculative
  abstractions, minimal comments (only for genuinely non-obvious *why*), and keep changes scoped to
  what was actually asked for.
