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

## Run it end to end

1. **Get the advisory text, never from memory.** The CVE Program's record
   (`https://cveproject.github.io/cve-schema/` shape; `containers.cna.descriptions[].value`),
   or for Microsoft CVEs the Security Update Guide, because the CVE record is title-only there.
   Store the text with the retrieval date and a content hash; a citation is only re-checkable
   against the text as captured.
2. **Extract.** Put the rules above in front of a model with the text beneath and take the YAML
   block it returns. The evaluation used `claude -p --model sonnet` on a subscription (no API
   key, no per-record cost); any model that follows instructions will do, but pin which one
   answered — `--output-format json` returns `modelUsage`, and the pipeline records it per
   record. Do not let the model fetch the advisory itself.
3. **Check the citations mechanically.** For every precondition, `cites` must be a verbatim
   substring of `advisory_text` after whitespace/NBSP normalisation. Reject the record on any
   failure. Validate the YAML against the record schema (`tests/fixtures/schema.json`).
4. **Review the reading, not the YAML.** The output's first part lists each precondition on a
   line with its quoted sentence under it. That is what a person checks: is the sentence really
   a condition (Rules 8–10), and is it filed under the right category?
5. **Compile the gate into a check.** Each decidable precondition becomes one deterministic
   predicate over something the host can show you — a config line, a loaded module, a running
   service — that quotes what it matched. Preconditions that no tool can decide are reported as
   *not assessed*, never silently dropped. Worked example: `checks/CVE-2024-38475/`.
6. **Run the check with the fleet tooling you have** (authenticated scanner audit, agentless
   host-configuration rule, Ansible, SSH) and keep the per-host three-way answer — present /
   absent / not assessed — with its evidence line.

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
| batch extractor with model pinning | `pipeline/extract.py` |
| 50 hand-verified reference records | `evaluation/reference/` |
| 30-record held-out set and scoring | `evaluation/heldout/` |
| worked host check | `checks/CVE-2024-38475/` |
