#!/usr/bin/env python3
"""Assemble the rebuild brief: one plain-text file from which a chat assistant with no access
to this repository can recreate the cited-precondition tool.

    python3 tools/build_rebuild_brief.py            # writes docs/precondition-tool-REBUILD-BRIEF.txt (+ 3 parts)

Everything load-bearing is copied from the repo's own files at build time — the frozen rules,
the record schema, the prompt contract, two reference records — so the brief cannot drift from
the tool. The generator refuses to write if the rules block or the schema are not present in
the output byte-for-byte. Prose sections are one line per paragraph so they paste cleanly;
YAML/JSON keep their line breaks because they have to.

No repository link, no personal names: the brief is meant to be pasted into a work tool.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
EVAL = PKG / "evaluation"
DOCS = PKG / "docs"
sys.path.insert(0, str(PKG / "pipeline"))
from extract import build_prompt  # noqa: E402

OUT = DOCS / "precondition-tool-REBUILD-BRIEF.txt"
PARTS = 3


SECTION_0 = """SECTION 0 — the rules and the tool, in plain English (a reading aid; Section 1 is the standard)

What a precondition is. A vulnerability advisory usually says more than "version X is vulnerable". It says things like "only when the rewrite module is loaded", "only if the SSL VPN service is running", "only when an attacker already holds a low-privilege account". Each of those is a condition a deployment must meet before the vulnerability applies to it. This tool calls them preconditions, and its one non-negotiable rule is that every precondition must quote, character for character, the advisory sentence it came from. A precondition with no quote does not exist. That is what makes the record checkable by a program, and what makes two people (or two models) comparable.

The ten rules, in plain words. The exact wording is Section 1 and it wins over this summary.
1. Only what the text says. Nothing goes into the structured fields that cannot be found in the advisory in front of you. Outside knowledge goes in the notes, labelled as outside.
2. Every precondition quotes its sentence exactly. No quote, no precondition.
3. One sentence can carry several preconditions. Many sentences carry none.
4. Sentences that are not preconditions are kept, not thrown away: fix and workaround history goes to remediation notes with one of five CSAF labels (vendor_fix, workaround, mitigation, none_available, no_fix_planned); descriptions of how the flaw works go to general notes. Both hold the sentence verbatim.
5. An empty list is a claim, and it must say which of two things it means: "genuinely nothing gates this; an affected version is enough", or "this text states no precondition". Those are different statements and the notes must start with one of them.
6. Never guess to fill a field. enabled_by_default is null unless the text states the default; version fields are null unless the text gives a range.
7. required_for_exploit is false when the condition only gates the known exploit and the text hedges that other paths may exist; true when it gates the vulnerability itself.
8. A sentence naming what the attacker must already hold (an account, a privilege level, local access, a prior compromise) or must be able to reach (a named service, port or interface) IS a precondition, even if it restates a CVSS metric, provided it names the specific thing. "Must hold" goes under deployment; "must reach" under network-reachability. A bare metric phrase that names nothing ("an unauthenticated remote attacker") stays a general note.
9. A sentence naming a specific thing the victim must open, run, load or process (a file type, a link, a document, a web site) IS a precondition, filed under deployment. "User interaction is required" naming nothing stays a general note.
10. A sentence that locates the flaw in a named optional component, service, feature, module or protocol IS a precondition that the component is present or enabled: deployment for presence ("the SSL VPN service is running"), configuration for an on/off state ("mod_rewrite is loaded").
The five categories: configuration (a setting or toggle), deployment (how or where it runs, including what the attacker must hold), api-usage (what the calling code invokes), network-reachability (what the attacker can reach or the host reaches out to), platform (an OS or runtime requirement).

How the tool works, one CVE at a time. Four steps; a model is used in exactly one of them.
Step 1, get the text (cve_text.py). Fetches the CVE record's description verbatim, or takes a pasted advisory from a file when the network is blocked. Writes the text to a file and never edits it. Every later check is against this captured text, so the tool records when it was fetched and from where.
Step 2, apply the rules (the model, in this chat or any other). The rules from Section 1 are placed above the text, with the exact task wording from Section 4, and the model returns one YAML record: identity (vendor, product), affected versions, the precondition list with quotes, remediation notes, general notes, notes. You supply vendor and product yourself, because rule 1 stops the model naming a vendor the text never mentions.
Step 3, check it (check_record.py, always with --input CVE.input.json so the captured text replaces whatever the model typed). No model. For every precondition it confirms the quote is really in the captured text (spaces and non-breaking spaces normalised, nothing else), checks the empty-list reading if the list is empty, and validates the whole record against schema.json. It prints PASS or FAIL per precondition with the quote, then ACCEPTED or REJECTED. A rejected record is not fixed by hand; you run step 2 again. Two rejections in a row are a finding about the advisory or the model, and are worth keeping.
Step 4, review the reading (you). Read each quoted sentence and ask three questions: is that really a condition the deployment must meet (rules 8 to 10), is the category right, is required_for_exploit right (rule 7). For an empty list, is the stated reading the honest one. A few minutes per record. This is the only step that needs a person, and it is the step that matters.

What comes out, and what it is for. A record whose every condition is traceable to a sentence. Later, a condition a script can decide (a config line, a loaded module, a running service) can be compiled into a deterministic check that runs on each host and answers present, absent or not assessed, with the evidence line — that is Section 9, and it is optional. Conditions no tool can decide are reported as not assessed, never dropped.

What is proven and what is not is in Section 10. Read it before trusting a number.
"""


def rules_block() -> str:
    prompt = (EVAL / "PROMPT.md").read_text(encoding="utf-8")
    return prompt[prompt.index("Rules:"):prompt.index("Here is the advisory")].rstrip() + "\n"


def prompt_contract() -> str:
    """The exact task text the batch run appended after the rules, with placeholders."""
    entry = {"source": "<SOURCE>", "source_url": "<SOURCE_URL>", "retrieved": "<YYYY-MM-DD>",
             "text": "<ADVISORY TEXT, VERBATIM>"}
    full = build_prompt("<CVE-ID>", entry, "<RULES>")
    return full[full.index("---"):]


def embedded_schema() -> str:
    """schema.json with its "$id" line removed (it names the repository); nothing else changes."""
    raw = (PKG / "tests" / "fixtures" / "schema.json").read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if not ln.lstrip().startswith('"$id"')]
    text = "\n".join(lines)
    json.loads(text)  # must still be valid JSON
    return text


def empty_reference() -> Path:
    for p in sorted((EVAL / "reference").glob("CVE-*.yaml")):
        if not yaml.safe_load(p.read_text(encoding="utf-8"))["expected"]["preconditions"]:
            return p
    raise SystemExit("no empty-list reference record found")


def worked_example_slice() -> str:
    md = (DOCS.parent / "checks" / "CVE-2024-38475" / "WORKED-EXAMPLE.md").read_text(encoding="utf-8")
    start = md.index("## 1. The three cited gates")
    end = md.index("## 5. ")
    return md[start:end].rstrip() + "\n"


def build() -> str:
    schema_text = embedded_schema()
    rules = rules_block()
    contract = prompt_contract()
    ref38475 = (EVAL / "reference" / "CVE-2024-38475.yaml").read_text(encoding="utf-8")
    empty_p = empty_reference()
    ref_empty = empty_p.read_text(encoding="utf-8")

    S = []  # sections
    S.append(f"""REBUILD BRIEF — cited-precondition extraction tool

READ THIS FIRST. You are going to rebuild a small, tested Python tool from this specification. You have no access to the original source; everything you need is in this text. Constraints, all hard: Python 3.8 or newer; standard library plus PyYAML only; the validator never calls a language model; no network is required except the optional CVE fetch, and that must have an offline fallback. Produce the files ONE AT A TIME in the order given, print each file in full, then stop and wait for me to say "next" — long outputs get cut off. Before producing anything, reply with the ten rule numbers and their first five words each, so I can see you read section 1 in full. Prose in this brief is one paragraph per line; YAML and JSON keep their line breaks and must be reproduced character for character where the brief says "verbatim".

What the tool does. A vulnerability advisory contains conditions that decide whether the vulnerability applies to a deployment ("only when module X is loaded", "only with feature Y enabled"). The tool turns an advisory's text into a structured record of those conditions — called preconditions — where EVERY precondition quotes the advisory sentence it rests on, character for character, and a mechanical check rejects any record whose quotation is not in the text. A language model does the extraction (you, in this chat, or any other model); the tool does everything around it: fetch the text, build the prompt, validate the record, check the citations. The record format and the validator are exact so records made here interchange with records made elsewhere.

Folder layout to create. Everything lives in one folder named precondition_tool with this exact layout: precondition_tool/RULES.md, precondition_tool/schema.json, precondition_tool/schema_check.py, precondition_tool/prompt_builder.py, precondition_tool/cve_text.py, precondition_tool/check_record.py, precondition_tool/fixtures/CVE-2024-38475.yaml, precondition_tool/fixtures/<second fixture>.yaml, precondition_tool/test_tool.py, precondition_tool/README.md (six lines: what it is, how to run check_record.py, how to run the tests, that it needs Python 3.8+ and PyYAML). If you can create files in a workspace, create the folder and the files directly. If you can only print, print each file in full with its path on the first line as a comment (for Python: "# precondition_tool/check_record.py"; for YAML: "# precondition_tool/fixtures/...") so I can save each one to the right place. The tests are run from inside the folder with: python3 -m pytest test_tool.py -q. The scripts import each other by plain module name (from schema_check import ...), so they must all sit in the same folder and be run from it.

If you are an agent that can run commands (for example a coding CLI): save this whole brief as precondition_tool/BRIEF.txt FIRST, then do not retype any section marked verbatim — slice it out of BRIEF.txt with a short Python snippet that copies the text between the <<<NAME_BEGIN>>> and <<<NAME_END>>> markers into the target file (RULES_BEGIN → RULES.md with the heading line prepended; SCHEMA_BEGIN → schema.json; FIXTURE_1_BEGIN → fixtures/CVE-2024-38475.yaml; FIXTURE_2_BEGIN → the second fixture, whose filename is stated in section 7; TASK_TEXT_BEGIN → the task-text constant in prompt_builder.py). Retyping is how a verbatim block drifts by one character and the citations stop matching. After writing the code, run the tests yourself, then perform the break-the-guard step in section 8 and show me the failing output before restoring.

Files to produce, in order: (1) RULES.md, (2) schema.json, (3) schema_check.py, (4) prompt_builder.py, (5) cve_text.py, (6) check_record.py, (7) the two fixture records into fixtures/, (8) test_tool.py, then README.md. Section 0 is a reading aid for people; Section 1 is the standard. Section 9 is optional and separate. Section 10 states what is and is not proven; keep it with the tool.
""")

    S.append(SECTION_0)

    S.append("""SECTION 1 — RULES.md (verbatim; this is the extraction standard, frozen; do not edit a word)

Write RULES.md containing exactly the block between the BEGIN and END markers. The first line of the file is "# Extraction rules (frozen)" and then the block.

<<<RULES_BEGIN>>>
""" + rules + """<<<RULES_END>>>
""")

    S.append("""SECTION 2 — schema.json (verbatim)

Write schema.json containing exactly the JSON between the markers.

<<<SCHEMA_BEGIN>>>
""" + schema_text.rstrip() + """
<<<SCHEMA_END>>>
""")

    S.append("""SECTION 3 — schema_check.py (the validator; behaviour must match this list exactly)

Provide three functions and one exception.

normalise_text(text) -> str: replace every U+00A0 (non-breaking space) with a plain space, collapse every run of whitespace (regex \\s+) to one space, strip leading and trailing whitespace. Nothing else is changed: case, punctuation and quotes are compared as-is.

citation_in_text(cites, advisory_text) -> bool: True when normalise_text(cites) is a substring of normalise_text(advisory_text).

class FixtureError(Exception): raised by the validator with a message beginning "fixture invalid:" followed by one line per problem, indented two spaces. Problems are COLLECTED, not raised on the first one, except that missing top-level keys are reported first and stop further checks.

validate_fixture(data, schema=None) -> None: load schema.json if none given; the value lists for "source", precondition "category" and remediation "category" are READ FROM schema.json, never hard-coded. Checks, in this order:
1. Top-level keys cve_id, ghsa_id, source, source_url, retrieved, advisory_text, expected must all be present; if any is missing, report each and stop.
2. cve_id matches ^CVE-\\d{4}-\\d{4,}$.
3. ghsa_id is null or matches ^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$.
4. source is one of the schema's "source" enum values.
5. source_url starts with "https://".
6. retrieved matches ^\\d{4}-\\d{2}-\\d{2}$.
7. advisory_text is non-empty after strip.
8. expected has identity, affected_versions, preconditions; if any missing, report and stop.
9. expected.identity has keys vendor, product, cpe, purl; vendor and product are non-empty strings; cpe and purl may be null but the KEYS must exist.
10. expected.affected_versions has keys introduced, fixed, excluded_fixed; excluded_fixed is a list.
11. expected.preconditions is a list. An EMPTY list is valid — it is an explicit claim (see Rule 5). Each item must have id, statement, category, enabled_by_default, required_for_exploit; id matches ^[a-z0-9]+(-[a-z0-9]+)*$ and is unique within the record; category is one of the schema's category enum; required_for_exploit is a boolean; enabled_by_default is true, false or null; if "cites" is present it must be a non-empty string AND citation_in_text(cites, advisory_text) must be true — otherwise report "expected.preconditions[i].cites is not a substring of advisory_text".
12. If expected.remediation_notes is present it is a list of objects with category (one of the schema's remediation enum) and non-empty text.
13. If expected.general_notes is present it is a list of non-empty strings.
Also provide load_fixture(path) that loads YAML and validates, returning the dict.

Worked cases your implementation must satisfy: (a) advisory contains "mod_rewrite in Apache" with a non-breaking space between "in" and "Apache", the citation has a plain space — PASS. (b) the citation is the same sentence re-wrapped over two lines — PASS. (c) one character changed in the citation ("mod_rewrit3") — FAIL, naming the precondition index. (d) preconditions is [] and the record is otherwise valid — validate_fixture passes; the Rule-5 reading is checked by check_record.py (section 6), not here.
""")

    S.append("""SECTION 4 — prompt_builder.py (the prompt contract; the task text below is verbatim)

build_prompt(cve_id, entry, rules) -> str returns: the full text of RULES.md (the rules string passed in), then a newline, then EXACTLY the task text between the markers with the angle-bracket placeholders replaced by the record's cve_id, source, source_url, retrieved and the advisory text. Two rules that are not negotiable: the advisory text goes between the BEGIN/END markers unchanged; and when the model's YAML comes back, the tool ALWAYS overwrites its advisory_text, source, source_url and retrieved with the captured values — the model is never trusted to echo the text back, so a citation is only ever checked against what was captured.

<<<TASK_TEXT_BEGIN>>>
""" + contract.rstrip() + """
<<<TASK_TEXT_END>>>

Also provide parse_record(raw) -> (dict|None, error|None): take the first ```yaml fenced block if present, else the whole reply; yaml.safe_load; error if not a mapping. And finalise(rec, cve_id, entry, vendor, product): substitute the captured fields as above; set expected.identity.vendor/product from the arguments when the model left them empty (Rule 1 stops the model naming a vendor the text never mentions — identity is supplied, not extracted); ensure identity has cpe and purl keys (null if absent); drop empty strings from general_notes; then validate_fixture. Return the rejection reason or None.
""")

    S.append("""SECTION 5 — cve_text.py (get the advisory text, verbatim, with an offline fallback)

CLI: cve_text.py CVE-ID [--out DIR] [--text FILE]. Two modes.
Online: GET https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{prefix}xxx/{cve}.json where year is the CVE's year and prefix is the numeric part with its last three digits removed (CVE-2024-38475 -> cves/2024/38xxx/CVE-2024-38475.json). From containers.cna: take every descriptions[] item whose lang starts with "en", join their value fields with a blank line; if configurations[] has English items append "\\n\\nConfigurations (stated by the CNA):\\n" and the values joined by blank lines; likewise workarounds[] under "Workarounds (stated by the CNA):". cna = containers.cna.providerMetadata.shortName. source = "cvelist"; source_url = https://www.cve.org/CVERecord?id={cve}; retrieved = today's date. If the record is not found, say so and exit 1; never reconstruct advisory text from memory.
Offline (--text FILE): read the pasted advisory from the file unchanged; source = "cvelist" unless --source is given; source_url must be supplied with --source-url (https://); retrieved = today.
Both modes write {cve}.advisory.txt (the text, unchanged) and {cve}.input.json ({cve: {source, source_url, retrieved, text, cna, has_configurations, has_workarounds}}) and print the text between "--- ADVISORY TEXT (verbatim) ---" and "--- END ---" markers.
Note for Microsoft CVEs: the CVE record is title-only; the Security Update Guide text is the real advisory. Use --text with that text pasted in.
""")

    S.append("""SECTION 6 — check_record.py (mechanical check of any record; no model, no network)

CLI: check_record.py FILE.yaml [more.yaml ...] [--input CVE.input.json]. --input is the capture written by cve_text.py ({cve: {source, source_url, retrieved, text, ...}}). When given, the record's advisory_text, source, source_url and retrieved are REPLACED from the capture before anything is checked and the tool prints "TEXT SUBSTITUTED FROM CAPTURE"; if the capture has no entry for the record's cve_id print "CAPTURE FAIL  no entry for <cve> in the --input file" and reject. When --input is NOT given print exactly "WARNING: advisory_text not substituted from capture; citations checked against the record's own text" before the result. This matters because a model that writes the YAML file itself types its own advisory_text; without substitution the citations are checked against the model's copy, and a paraphrasing model would pass its own citations. Always run with --input. For each file print "== FILE", then for every precondition one line "PASS  <id>  [<category>]" or "FAIL  <id>  [<category>]" followed by a line '      cites: "<the citation or (none)>"', using citation_in_text against the record's advisory_text. If the precondition list is empty, print PASS or FAIL for "(empty list) notes must begin with one of ('genuinely nothing gates this', 'this text states no precondition')" — the notes field must START with one of those two phrases — followed by the notes. Then run validate_fixture and print "SCHEMA PASS" or "SCHEMA FAIL  <message>". Then "ACCEPTED  n precondition(s)" or "REJECTED  n precondition(s)". Exit 0 only if every file is accepted, 1 otherwise, 2 if no arguments (print usage). A failing record is never fixed by the tool.

Extraction at work, without any CLI: open RULES.md, paste its whole contents into this chat, paste the advisory text beneath it between the BEGIN/END markers from section 4 with the CVE id and source lines filled in, and save the YAML block the model returns as CVE-ID.yaml. Then run check_record.py CVE-ID.yaml --input CVE-ID.input.json — never without --input, because the model wrote the file. Record which model answered in the record's notes, because that is not captured automatically this way.
""")

    S.append("""SECTION 7 — two fixture records (verbatim; these are hand-verified reference records and the tests depend on them)

Write fixtures/CVE-2024-38475.yaml:

<<<FIXTURE_1_BEGIN>>>
""" + ref38475.rstrip() + """
<<<FIXTURE_1_END>>>

Write fixtures/""" + empty_p.name + """ (an empty-list record with its Rule-5 reading):

<<<FIXTURE_2_BEGIN>>>
""" + ref_empty.rstrip() + """
<<<FIXTURE_2_END>>>
""")

    S.append("""SECTION 8 — test_tool.py (pytest; all must pass, and one must be shown to fail first)

1. Both fixtures load and validate (load_fixture) without error.
2. check_record.py on fixtures/CVE-2024-38475.yaml exits 0, prints "SCHEMA PASS", prints exactly three "PASS  " lines and no "FAIL".
3. Copy CVE-2024-38475.yaml to a temp file, change "mod_rewrite" to "mod_rewrit3" in the FIRST precondition's cites only; check_record.py exits 1 and prints "FAIL  mod-rewrite-in-use".
4. Copy it again, set preconditions to [] and notes to "nothing to say"; check_record.py exits 1 and prints "(empty list)".
5. The empty-list fixture passes check_record.py (its notes begin with a Rule-5 reading).
6. normalise_text: "a\\u00a0b" == "a b"; "a\\n   b" == "a b"; citation_in_text is case-sensitive.
7. build_prompt output contains the rules string verbatim, the two ADVISORY_TEXT markers, and the advisory text between them.
8. Substitution guard. Write fixtures/paraphrase/CVE-2024-38475.paraphrase.yaml: a copy of the reference record whose advisory_text is a PARAPHRASE (same meaning, different words) and whose every cites is copied from that paraphrase, so the record is internally consistent. Write fixtures/paraphrase/CVE-2024-38475.input.json holding the REAL advisory text from the reference record under the key "CVE-2024-38475" with source, source_url, retrieved. Then: (a) check_record.py on the paraphrase WITHOUT --input exits 0, prints ACCEPTED and the WARNING line; (b) WITH --input it exits 1, prints TEXT SUBSTITUTED FROM CAPTURE, a "FAIL  mod-rewrite-in-use" line and REJECTED; (c) the reference record WITH --input exits 0 and prints TEXT SUBSTITUTED FROM CAPTURE; (d) --input pointing at a capture that lacks the CVE exits 1 with CAPTURE FAIL.
Prove the guard is real, twice: temporarily make normalise_text return its input unchanged, run test 6 and test 2, watch at least one fail, restore. Then temporarily make the --input substitution a no-op, run test 8(b), watch it fail, restore. A test that has never failed is a guess.
""")

    S.append("""SECTION 9 — OPTIONAL, second build: a host-side check compiled from a record (the pattern, using CVE-2024-38475)

Skip this until sections 1–8 pass. It shows how a decidable precondition becomes a deterministic script that a scanner or agent runs per host, quoting the config line it matched. The three gates, the predicate read from Apache's own fix, and the fixture table with expected verdicts follow. Output shape per host: {cve_id, host, checked_at, files_scanned, gates: [{id, verdict: present|absent|not_assessed, evidence: [{file, line, text}], detail}]}; exit 2 if any decidable gate is present, 0 otherwise, 1 on error; a --format text mode printing one line per gate and the evidence lines beneath. Standard library only; Python 3.8+; the third gate is never decided.

""" + worked_example_slice())

    S.append("""SECTION 10 — what is and is not proven (keep this with the tool)

The standard was evaluated on 50 hand-verified reference records and a separate 30-record held-out set. On the held-out set, two independent model readers agreed on 89% of preconditions (95% interval 74–95%), with every citation valid and every empty list agreed. Both readers were models of the same family, so treat 89% as an upper bound: a comparison against a human reader has not been done. The host-check pattern in section 9 is proven on one CVE with eight fixtures; it is an example of the shape, not a library. Anything a check cannot decide is reported as not_assessed, never silently dropped. The record format, the rules and the validator are shared verbatim between this rebuild and the original so results compare; if you change a rule, you have a different standard and the numbers above no longer apply.
""")

    text = "\n".join(S)
    # hard guarantees
    assert rules in text, "rules block not verbatim in output"
    assert schema_text.rstrip() in text, "schema.json not verbatim in output"
    assert ref38475.rstrip() in text and ref_empty.rstrip() in text
    for banned in ("github.com/scolly2683", "scolly2683", "vuln-evidence-registry"):
        assert banned not in text, f"banned string in brief: {banned}"
    return text


def split_parts(text: str, n: int) -> list[str]:
    """Split on section boundaries into n parts of roughly equal size, each self-labelled."""
    secs = re.split(r"(?m)^(?=SECTION \d+ — |REBUILD BRIEF — )", text)
    secs = [s for s in secs if s.strip()]
    parts: list[list[str]] = [[] for _ in range(n)]
    target = len(text) / n
    k = 0
    size = 0
    for s in secs:
        if size >= target and k < n - 1:
            k += 1
            size = 0
        parts[k].append(s)
        size += len(s)
    out = []
    for i, chunk in enumerate(parts, 1):
        head = f"[PART {i} OF {n} of the rebuild brief. Paste all {n} parts in order before doing anything.]\n\n"
        out.append(head + "".join(chunk))
    return out


def main() -> int:
    DOCS.mkdir(exist_ok=True)
    text = build()
    OUT.write_text(text, encoding="utf-8")
    for i, part in enumerate(split_parts(text, PARTS), 1):
        (DOCS / f"precondition-tool-REBUILD-BRIEF-part{i}of{PARTS}.txt").write_text(part, encoding="utf-8")
    print(f"wrote {OUT}: {len(text.split())} words, {len(text)} chars, {PARTS} parts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
