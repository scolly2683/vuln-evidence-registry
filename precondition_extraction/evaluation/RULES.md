# The cited-precondition extraction standard, as run

**Status:** the rules below are frozen. They are reproduced character for character from the
prompt file the evaluation ran with (`PROMPT.md`), and a test fails if this document and that
file ever differ. The measured agreement figures at the end were obtained under exactly this
text.

## What it produces

For one advisory, one record: the vendor and product, the affected version range, and a list of
**preconditions** — the conditions a deployment must meet for the vulnerability to apply — each
tagged with a category and each **citing the advisory sentence it rests on, verbatim**. A
mechanical check confirms every citation is a substring of the advisory text (whitespace and
non-breaking spaces normalised); a record that fails that check is rejected, not corrected.

An empty list is itself a claim and must say which of two things it means: "genuinely nothing
gates this; an affected version is enough", or "this text states no precondition".

## The rules (verbatim)

```
Rules:
1. Everything in the record must be derivable from the advisory text in front of you.
   Outside knowledge goes only in notes, labeled as outside the text.
2. Every precondition cites the exact sentence it rests on, quoted character-for-character.
   No citation, no precondition.
3. One sentence can carry several preconditions; several sentences can carry none.
4. Sentences that are NOT preconditions are kept, not dropped: fix/workaround history goes
   to remediation_notes with a CSAF category (vendor_fix, workaround, mitigation,
   none_available, no_fix_planned); flaw/attacker-mechanism description goes to
   general_notes. Both hold verbatim sentences.
5. An empty preconditions list is a claim with two distinct readings — say which applies:
   "genuinely nothing gates this; an affected version is enough" or "this text states no
   precondition" (and flag it if you know a real gate exists outside the text).
6. Say plainly when something can't be determined: enabled_by_default is null unless the
   text states the default; version fields are null when the text gives no range, with the
   messy reality explained in notes. Never guess to fill a field.
7. required_for_exploit is false when a condition gates only the known exploit and the
   advisory hedges that other paths may exist; true when it gates the vulnerability itself.
8. A sentence that names what the attacker must already hold (an account, a privilege level,
   local access, a prior compromise, a specific artefact) or must be able to reach (a named
   service, interface, port or component) IS a precondition, even when it restates a CVSS
   metric in prose, provided it names the specific thing. File "must hold" gates under
   deployment and "must reach" gates under network-reachability. A bare metric restatement
   that names nothing ("an unauthorized attacker over a network") remains a general note.
9. A sentence naming a specific artefact the victim must open, execute, load or process (a
   file type, a link, a document, a web site) IS a precondition — file it under deployment
   until the standard gains a user-interaction category. "User interaction is required"
   naming nothing remains a general note.
10. A sentence that locates the flaw in a named optional component, service, feature, module
   or protocol IS a precondition that the component is present or enabled — deployment for
   presence ("the Remote Access SSL VPN service is running"), configuration for an
   enable/disable state ("mod_rewrite is loaded", "the remoting CLI protocol is enabled").

Precondition categories: configuration (a setting/toggle), deployment (how/where it runs),
api-usage (what the calling code invokes), network-reachability (what the attacker can
reach or the host reaches out to), platform (OS/runtime requirement).

Output two parts, in order:
1. THE READING — each precondition on one line (short-slug-id, category, required?,
   default?) with its verbatim cited sentence quoted beneath, then each remediation/general
   note with its sentence.
2. THE RECORD — one YAML block: cve_id (null if unassigned), ghsa_id, source, source_url,
   retrieved (today), advisory_text (verbatim), then expected: identity {vendor, product,
   cpe, purl}, affected_versions {introduced, fixed, excluded_fixed, notes},
   preconditions [{id, statement, category, enabled_by_default, required_for_exploit}],
   remediation_notes, general_notes, notes.

Calibration example (Log4Shell, CVE-2021-44228): the sentence "An attacker who can control
log messages or log message parameters can execute arbitrary code loaded from LDAP servers
when message lookup substitution is enabled." yields THREE preconditions — the config
toggle, attacker-influenced log input, and outbound JNDI/LDAP reachability — while "From
log4j 2.15.0, this behavior has been disabled by default." is fix history (vendor_fix
remediation note) that also establishes the toggle's earlier default, and the advisory's
opening flaw-description sentence is a general_note, not a precondition.
```

## Run it at work, exactly — step by step

This is the same sequence the evaluation ran, one CVE at a time, using three small commands
that call the pipeline's own functions. It was executed end to end on 5 September 2026 on
CVE-2026-9586 (a CISA KEV entry not in any evaluation set); the real output is pasted under
each step so you know what "worked" looks like.

**Step 0 — what you need, once.**

- A computer with Python 3.8 or newer (`python3 --version`) and the PyYAML package
  (`pip install pyyaml`).
- The Claude Code command-line tool, signed in. A subscription is enough: no API key, no
  per-record cost. Check with `claude --version`. (If you cannot install it, Step 3 has a
  copy-and-paste alternative.)
- A copy of the `precondition_extraction` folder from the registry — download the repository
  as a zip, or `git clone`. Open a terminal in that folder. Everything below is run from there.

**Step 1 — get the advisory text, verbatim.** Never type or paste it from memory.

```
python3 tools/cve_text.py CVE-2026-9586
```

What it prints: the source (the CVE Program's record, or Microsoft's Security Update Guide
for Microsoft CVEs), the retrieval date, whether the CNA filled the `configurations` field,
and the text between `--- ADVISORY TEXT ---` markers. It writes `CVE-2026-9586.advisory.txt`
and `CVE-2026-9586.input.json`. If it says "no record", the id is mistyped or not yet
published. Do not edit the text file.

**Step 2 — look up the vendor and product.** The rules stop the model from naming a vendor
the text never mentions (Rule 1), so you supply the record's identity yourself — from CISA
KEV, the CVE record's `affected` block, or the vendor's page. Two words are enough.

**Step 3 — run the rules and check the result.** One command does Steps 1–4 of the pipeline:

```
python3 tools/extract_one.py CVE-2026-9586 --vendor Sangoma --product Switchvox
```

Real output from the run on 5 September 2026:

```
[1/4] fetching advisory text for CVE-2026-9586 …
      source=cvelist cna=SRA chars=498
[2/4] building the prompt from the frozen rules …
[3/4] running `claude -p --model sonnet --output-format json` …
      answered by: claude-sonnet-5
[4/4] parsing, substituting the canonical text, validating, checking citations …
      ACCEPTED — 1 precondition(s), every citation verified
      record: CVE-2026-9586.yaml

THE READING (what to review):
  - pa-endpoint-reachable  [network-reachability, required=True, default=None]
      cites: "The /pa endpoint processes XML content beginning with <PolycomIPPhone> and
      directly concatenates the user-controlled PhoneIP value into PostgreSQL queries
      without sanitization or parameterization."
```

It took 38 seconds. Four files appear: `CVE-2026-9586.yaml` (the record),
`.advisory.txt`, `.input.json` (exactly what the model was shown) and `.run.json`, which
records that the model asked for was `sonnet` and the model that answered was
`claude-sonnet-5`. Keep all four together; the record is only re-checkable against the text
it was made from.

If the last line says **REJECTED**, the reason is printed (a citation that is not in the
text, a missing field, a YAML error) and the raw reply is kept in `.rejected.txt`. Do not
fix the YAML by hand. Re-run; if it is rejected twice, keep the rejection — that is a finding
about the advisory or the model, and the evaluation recorded those too.

*Without the command-line tool:* open `evaluation/PROMPT.md`, paste its whole contents into
a chat with any capable model, then paste the advisory text from Step 1 beneath it, and
save the YAML block it returns as `CVE-2026-9586.yaml`. Then run Step 4 on that file. The
model's name is not recorded automatically this way; write it in the record's `notes`.

**Step 4 — check any record mechanically.** `extract_one.py` already did this. Run it again
on a record from a chat window, or on any record you were given:

```
python3 tools/check_record.py CVE-2026-9586.yaml
```

Output is `SCHEMA PASS`, then one `PASS` or `FAIL` line per precondition with its quoted
sentence, then a count. Any `FAIL` means the record is not accepted. An empty precondition
list passes only if `notes` starts with one of the two readings Rule 5 requires.

**Step 5 — review the reading, not the YAML.** Read each precondition's quoted sentence and
ask three questions: is that sentence really a condition the deployment must meet (Rules
8–10), is it filed under the right category, and is `required_for_exploit` right (Rule 7)?
For an empty list, is the stated reading the honest one? This is the only step that needs
a person, and it is a few minutes per record.

**Step 6 — compile a decidable gate into a check.** Give the record to the model with one
instruction: "write a deterministic script that decides gate *X* from what the host can
show — a config line, a loaded module, a running service — and quotes what it matched;
say `not_assessed` for anything it cannot decide." Insist on three things before you trust
it: a fixture folder with at least one positive and one negative for each verdict, a test
that fails when the predicate is deliberately broken, and evidence lines in the output.
`checks/CVE-2024-38475/` is the template: script, eight fixtures, 37 tests, and the
document that explains the predicate.

**Step 7 — run the check with the fleet tooling you have.** Tenable (`CMD_EXEC` audit
item), Qualys (CAR script + script-result control), Wiz (custom host-configuration rule),
Defender live response (spot checks only), Ansible or SSH for the rest. The worked example
gives each in its own syntax.

**Step 8 — keep the three-way answer per host, with its evidence line.** *Present*: the
version finding stands, patch. *Absent*: the finding is a per-host `not_affected` with a
citable reason. *Not assessed*: it stays a version finding, and the report says why.

## What is and is not proven

- On a 30-record held-out set the extraction, run by one model and re-read blind by a second,
  agreed on **89%** of gates (95% interval 74–95%), kappa 0.93 on the record-level decision,
  with every citation valid and every empty list agreed. Both readers were models of the same
  family; treat 89% as an upper bound. **A human-reader comparison has not been done.**
- The measured usefulness of the source field (CVE `configurations`) is on a curated, exploited
  population only (CISA KEV) and rests on 13 filled records from two vendors.
- The check layer is proven on one CVE with eight fixtures and a deliberately-broken-then-
  restored test run. It is an example of the shape, not a library.

## Files

| what | where |
|---|---|
| the frozen prompt | `evaluation/PROMPT.md` |
| record schema | `tests/fixtures/schema.json` |
| citation checker | `schema.py::citation_in_text` |
| single-CVE recipe commands (Steps 1, 3, 4) | `tools/cve_text.py`, `tools/extract_one.py`, `tools/check_record.py` |
| batch extractor with model pinning | `pipeline/extract.py` |
| 50 hand-verified reference records | `evaluation/reference/` |
| 30-record held-out set and scoring | `evaluation/heldout/` |
| worked host check | `checks/CVE-2024-38475/` |
