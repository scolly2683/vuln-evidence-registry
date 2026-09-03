# First run at scale — 170 exploited edge CVEs

*2026-09-03. Every number here comes from `runs/edge-2023plus/` (170 records) and
`data/analysis_edge_2023plus.json`. Reproduce with `python3 analyse.py --run
runs/edge-2023plus`. Family bucketing is keyword-based and is a reading aid, not a
measurement — the categories table beside it is exact, taken from the records.*

## What was run

170 KEV CVEs from 2023 onward on edge/perimeter products — the stratum the controls ledger
is built on and where the standard scores best (recall 0.97 on the 50-record gate). All 170
are `cvelist`-sourced, so the weak MSRC stratum (recall 0.53) is absent by construction.
Extraction by `claude -p --model sonnet` against the ten rules, 38 minutes wall clock,
**no API key and no per-record cost** — the CLI authenticates against the owner's
subscription.

**Every record was mechanically checked**: canonical `advisory_text` substituted so drift
cannot occur, every `cites` verified a substring of it, then `validate_fixture`. 14 records
were rejected on the first pass; all 14 were one harness bug (`cpe`/`purl` are
required-but-nullable and the prompt's output shape omitted them), fixed, re-run clean.
**Zero records failed on citation validity, parsing, or judgement.**

## The headline finding: the empty rate is a source problem, not a method problem

|  | CVEs | mean preconditions | records stating no precondition |
|---|---|---|---|
| CNA filled the `configurations` container | 13 | **2.54** | **0 / 13 (0%)** |
| CNA did not | 157 | 1.15 | **50 / 157 (32%)** |

Where the CNA fills the schema-native field, the extractor **never comes up empty** and
finds **2.2× more gates**. Where it does not, a third of exploited edge CVEs yield nothing
at all. Median advisory text: 273 characters for the empty records, 388 for the gated ones.

This is the number that matters for the standards argument in `STANDARDS.md`. The fix for
the 29% empty rate is not a better model or more rules — it is ~21 CNAs filling a container
that has existed in CVE 5.x all along and is used on **1.2% of KEV**. The measurement is the
lever, and this is the measurement.

## The two ledger questions

| question | result |
|---|---|
| attacker must already hold something (credentials, account, local access, prior compromise) | **52 / 170 (31%)** |
| gated on an exposed management surface (portal, gateway, admin/web UI, VPN) | **34 / 170 (20%)** |
| both | 14 / 170 (8%) |
| neither — running an affected version is effectively enough | **98 / 170 (58%)** |

**The 31% confirms the sample.** The 50-record read suggested ~25% of exploited CVEs require
the attacker to already hold something; at 3.4× the population it is 31%. This is the claim
that survives contact with scale, and it is the one worth putting in front of a deployer:
for roughly a third of *actively exploited* edge CVEs, "internet-facing and unpatched" is
the wrong mental model — something else has to go wrong first.

**The 20% does NOT confirm the sample, and the earlier figure should not be repeated.** The
50-record read found one gate ("remote-access portal exposed") behind **7 of 20 edge CVEs
(35%)**. At scale it is 20%. The small sample overstated it by three-quarters. The finding
survives in kind — an exposed management surface is still the single largest *shared* gate,
and it concentrates hard by vendor — but not in size.

Concentration among the 34: Cisco 10, Palo Alto 6, Citrix 6, Check Point 2, F5 2, then a
long tail of one apiece (Fortinet, SonicWall, Juniper, Zyxel, Barracuda, TP-Link, Apache).

## Categories, exact

| category | n | share |
|---|---|---|
| deployment | 107 | 50.0% |
| network-reachability | 60 | 28.0% |
| configuration | 43 | 20.1% |
| platform | 4 | 1.9% |
| api-usage | 0 | 0% |

`deployment` at half of all gates is rules 8 and 9 doing their work — "the attacker must
already hold" and "the victim must act" now have a home. `api-usage` at zero is expected and
correct: it is a library-consumer category, and this slice is appliances.

## What the run does not show

- **1.26 preconditions per CVE**, against 1.76 in the hand-verified reference set. The
  pipeline extracts less per CVE than a careful reader does; recall on the gate is 0.84, and
  nothing here contradicts that. Treat these counts as a floor.
- **The 13 CVEs with a `configurations` container are not comparable to the reference set**,
  which read NVD descriptions only. On those records the pipeline reads richer source, so a
  pipeline-vs-reference score there measures the source ladder, not the extractor.
- **Edge only, 2023+.** Nothing here generalises to Microsoft (gate recall 0.53) or to the
  general CVE population, where `configurations` coverage is unlikely to be *higher* than
  KEV's 1.2%.
- **Family bucketing is keyword-based.** 28 of 214 preconditions (13%) matched no family and
  are printed in full by `analyse.py` — several are real gates the families do not yet cover
  (a licence applied, a serial number known, a self-hosted-vs-cloud distinction). That pile
  is where the next family comes from, not noise to be tidied away.
