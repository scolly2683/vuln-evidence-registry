# Precondition tool — handover for engineers

**What you are being handed:** one text file, `precondition-tool-REBUILD-BRIEF.txt`, from which
a coding assistant rebuilds a small, tested Python tool. Python 3.8+, PyYAML, nothing else. No
database, no network needed except an optional CVE fetch with an offline fallback. Plain-English
explanation of the rules and the tool is Section 0 of the brief; read that first.

**What the tool does in one sentence:** turns a vulnerability advisory into a record of the
conditions under which the vulnerability actually applies, where every condition quotes the
advisory sentence it came from and a program rejects any that does not.

## 1. Build it (about an hour, once)

1. Make an empty folder. Save the brief into it as `BRIEF.txt`.
2. Open your coding assistant CLI in that folder (Copilot CLI with Kimi was the intended target;
   any agent that can write files and run commands works). Paste this as the first message:

```
Read BRIEF.txt in full and follow it. You can write files and run commands. First reply with
the ten rule numbers and the first five words of each. Then build the precondition_tool folder
exactly as specified, slicing every section marked verbatim out of BRIEF.txt with a script
rather than retyping it. Run the tests. Then do the break-the-guard step in Section 8, show me
the failing output, and restore. Do not do Section 9.
```

3. Expect: ten files under `precondition_tool/`, a green test run, and **one deliberate failing
   run before it**. If the assistant skips the failing run, ask for it. A test that has never
   failed proves nothing.
4. If the assistant cannot echo the ten rule numbers at the start, the paste was cut. Use the
   three `part1of3` … `part3of3` files instead, in order.

## 2. Accept it (ten minutes)

From inside `precondition_tool/`:

```
python3 -m pytest test_tool.py -q                    # all green
python3 check_record.py fixtures/CVE-2024-38475.yaml # three PASS lines, SCHEMA PASS, ACCEPTED
```

Then the one check that matters: open `RULES.md` and `schema.json` and confirm they are
byte-identical to the blocks between the `<<<RULES_BEGIN>>>` / `<<<SCHEMA_BEGIN>>>` markers in
`BRIEF.txt`. A `diff` is enough. If they differ by one character, records made here will not
match records made elsewhere. Reject the build.

## 3. Run it (one CVE, four steps)

```
python3 cve_text.py CVE-2024-38475                   # 1. fetch the text; or --text file.txt if GitHub is blocked
```
Then, in the assistant, one message: *"Read RULES.md, apply it to CVE-2024-38475.advisory.txt
using the prompt from prompt_builder.py, output only the YAML record, save it as
CVE-2024-38475.yaml. Vendor is Apache, product is HTTP Server."* You supply vendor and product;
rule 1 stops the model naming a vendor the text never mentions.

```
python3 check_record.py CVE-2024-38475.yaml --input CVE-2024-38475.input.json   # 3. PASS/FAIL per condition, then ACCEPTED or REJECTED
```
Always with `--input`. It replaces the text the model typed with the captured text before
checking. Without it the tool prints a warning and the result is unverified.
4. A person reads each quoted sentence: is it really a condition, is the category right, is
   `required_for_exploit` right. Minutes per record. **Rejected records are never edited by
   hand**; run step 2 again. Two rejections in a row are a finding, keep them.

Write the model's name into the record's `notes` every time. Different models were not
measured against each other.

## 4. Maintain it (the rules that keep it honest)

- **Never edit `RULES.md`.** It is a frozen standard; the agreement figures in Section 10 were
  measured under exactly that text. A changed rule is a different standard with no numbers.
  If a change is genuinely needed, version it (`RULES-v2.md`), re-run every fixture, and stop
  quoting the old figures.
- **`schema.json` changes only by adding optional fields.** Never rename or remove; records
  already written must keep validating.
- **Add a fixture for every rejection you learn from.** A record that was rejected for a good
  reason becomes a test case that must keep failing. Fixtures are the regression suite.
- **Keep the four files of every run together**: `.advisory.txt`, `.input.json`, `.yaml`, and
  the notes naming the model. A citation is only re-checkable against the text it was made
  from; the CVE record on the internet can change.
- **Re-fetch and re-check quarterly** for records you rely on. If the advisory text changed,
  the citations may no longer match, and that is the signal you want.
- **Never accept a record checked without `--input`.** The warning line exists so that a
  check against the model's own copy of the text is visibly second-class.
- **The validator never calls a model.** If someone proposes "let the model fix the citation",
  the answer is no; that is the one thing the design exists to prevent.
- **The optional host-check (Section 9) is a pattern, not a library.** One reviewed check per
  advisory, with fixtures for every verdict and a test that fails when the predicate is broken.
  Conditions no script can decide are reported `not_assessed`, never dropped.

## 5. What is and is not proven

Two independent model readers agreed on 89% of conditions on a 30-record held-out set (95%
interval 74–95%). Both were models of the same family; treat 89% as an upper bound. **No
human-reader comparison has been done.** The host-check pattern is proven on one CVE. Nothing
in this handover has been run on a live scanner tenant.

## 6. Files

| file | purpose |
|---|---|
| `precondition-tool-REBUILD-BRIEF.txt` | the whole specification; the assistant builds from it |
| `precondition-tool-REBUILD-BRIEF-part1of3.txt` … `part3of3.txt` | the same text split for chats that truncate pastes |
| this document | build, accept, run, maintain |
