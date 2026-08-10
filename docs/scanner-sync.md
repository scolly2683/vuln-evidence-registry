# Scanner sync — keeping Qualys and Wiz honest against the registry

`tools/sync_suppressions.py` closes the loop between the suppression
registry (source of truth) and the scanners (sinks). Both commands are
**offline** — they read console exports, not APIs — so they work on day
one, before any API onboarding.

## Safety: context-conditional suppressions are never blanket-synced

A suppression with a `context:` predicate (e.g. `config_vulnerable: false`)
is conditional on a per-finding fact the scanner **cannot evaluate**. Pushing
it as a blanket QID/CVE exclusion would silence *every* instance — including
genuinely vulnerable ones whose context differs. So `plan` holds these back
in a `context_scoped_do_not_blanket_sync` list for a human to implement as a
*scoped* scanner rule (asset-tag / dynamic list) or leave to the registry
alone. Only unconditional verdicts (a wrong QID, a component-absent CVE)
become blanket exclusions.

## plan — what the tools *should* be suppressing

```bash
python tools/sync_suppressions.py plan --registry registry
```

Computed from **active** suppressions only: expired rules drop out of the
plan automatically, so lapsing a `review_by` date is all it takes for
detections to resurface on the next sync. QID matches drive the Qualys
exclusion list; CVE matches (or the `vex:` block's CVE for QID-clustered
rules) drive the Wiz ignore-rule list.

## reconcile — what the tools are *actually* suppressing

```bash
python tools/sync_suppressions.py reconcile --registry registry \
    --tool qualys --actual qualys-exclusions.txt     # any text/CSV with QIDs
python tools/sync_suppressions.py reconcile --registry registry \
    --tool wiz --actual wiz-ignore-rules.json        # JSON list of CVEs/objects
```

Four-way classification:

| Result | Meaning | Action |
|---|---|---|
| `managed` | in tool and in registry | none |
| `MISSING` | in registry, not in tool | add the exclusion/ignore rule |
| `EXPIRED` | in tool; registry rule past `review_by` | **remove** — the lease lapsed |
| `UNMANAGED` | in tool with **no registry rule** | the failure mode this exists for: an unaudited, unexpiring risk acceptance — adopt it into the registry (`propose-suppression`) or remove it |

Exit code 1 on any drift — wire it into CI or a weekly job and treat a red
run as a real signal. The weekly rhythm: export from both consoles,
reconcile, clear the diff.

## Later: live apply

Once API access is onboarded, the apply step replaces the manual console
work: Qualys — a static search list of the planned QIDs referenced from an
exclusion option profile (`/api/2.0/fo/qid/search_list/static/`); Wiz —
ignore rules via the GraphQL API. Tag both as registry-managed so
reconcile can distinguish ours from hand-made ones. The plan/reconcile
contract doesn't change — apply just automates the "clear the diff" step.
