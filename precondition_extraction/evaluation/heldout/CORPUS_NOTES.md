# Corpus defects found during the held-out build — recorded, deliberately NOT fixed

Found while building the held-out reference on 2026-09-03. Each is a real defect in the
advisory text the extractor reads. **None was fixed**, because the held-out set is drawn and
`RULES_FROZEN.json` pins the rules to a specific corpus — editing input text mid-experiment
is precisely the contamination the freeze exists to prevent. Fix them after the held-out
number is recorded, then re-draw if the fix changes text the set depends on.

## 1. The CNA description elides the product (15 CVEs)

`CVE-2017-6742` reads, verbatim:

> A vulnerability in the SNMP implementation of could allow an authenticated, remote attacker
> to cause a reload of the affected system…

"of could" — the product name is simply absent. This is upstream CVE data, not a fetch bug:
the CNA wrote the description assuming the product lives in CVE 5.x's structured `affected[]`
field, and `pipeline/fetch_sources.py::cvelist_text()` reads only `descriptions` plus the
`configurations` / `workarounds` containers.

Swept over all 1,694 KEV inputs:

| shape | CVEs |
|---|---|
| a preposition immediately followed by a verb (`of could`, `in allows`) | **15** |
| a double space mid-sentence where a product name would sit | 12 |
| empty quotes or brackets | 28 |

**Effect on the experiment, and why it is not a problem for it.** The annotator hit
CVE-2017-6742, refused to name Cisco from outside knowledge, wrote `identity.vendor:
unspecified` and confined the real name to `notes` labelled as outside the text. Rule 1 held.
The record is still perfectly scorable — the gates and their citations are unaffected, since
the elision is in the identity clause, not the vector clause.

**The fix, for afterwards.** Read `containers.cna.affected[]` (vendor / product / versions)
in `cvelist_text()` and prepend a labelled identity line, the same way `configurations` and
`workarounds` are appended under headings. That is strictly more text, so it can only change
records whose identity was previously unreadable — but it *is* a text change, so it needs its
own draw.

## 2. The held-out edge stratum is entirely pre-2023

Not a defect, a consequence of the draw: the 170-CVE `edge-2023plus` run consumed the recent
edge population, and the held-out set excludes it. So held-out edge is 2014–2022 (Fortinet
2022, Citrix 2019, Cisco ASA 2014, Juniper 2020, …) where the 50-record reference's edge
stratum skewed recent.

Older CNA descriptions are terser, so a higher empty rate on this stratum is expected and is
**not** evidence the extractor got worse. Any comparison of held-out edge against the
reference's edge stratum is comparing two different populations, and the write-up must say so
rather than presenting it as a like-for-like drop.

## 3. Advisory text is not always one language of prose

`CVE-2026-31431` is a Linux kernel commit message — a revert, its rationale and a commit
hash, with no attacker, impact or vector. `CVE-2016-7262` past its title is entirely
update-applicability boilerplate. Both are legitimately in KEV. The standard handles them
(rule 5's two empty readings, remediation notes for the boilerplate), but they are a reminder
that "advisory text" is a category containing several genres, and the empty rate is partly a
measure of genre mix rather than of CNA diligence.
