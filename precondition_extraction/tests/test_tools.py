"""The single-CVE tools (precondition_extraction/tools/) behind the step-by-step recipe.

Offline only: these tests never call the network or `claude`. They pin the parts of the
recipe that can be checked without them — the record checker's PASS/FAIL logic against a
committed reference record and a deliberately broken copy, and the fetch helper's handling
of a CVE record shape. The end-to-end run with the model was done by hand on 2026-09-05
(CVE-2026-9586, claude-sonnet-5, accepted, 43 s) and its output is quoted in RULES.md.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

PKG = Path(__file__).resolve().parents[1]
TOOLS = PKG / "tools"
REFERENCE = PKG / "evaluation" / "reference" / "CVE-2024-38475.yaml"

sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(PKG / "pipeline"))


def _check(path: Path):
    return subprocess.run([sys.executable, str(TOOLS / "check_record.py"), str(path)],
                          capture_output=True, text=True)


def test_check_record_passes_a_reference_record():
    r = _check(REFERENCE)
    assert r.returncode == 0, r.stdout
    assert "SCHEMA PASS" in r.stdout and "FAIL" not in r.stdout
    assert r.stdout.count("PASS  ") == 3  # the three cited gates


def test_check_record_fails_a_citation_that_is_not_in_the_text(tmp_path):
    """The guard must fail: change one character of a citation and the tool must say FAIL."""
    data = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
    data["expected"]["preconditions"][0]["cites"] = data["expected"]["preconditions"][0]["cites"].replace("mod_rewrite", "mod_rewrit3")
    bad = tmp_path / "CVE-2024-38475.yaml"
    bad.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    r = _check(bad)
    assert r.returncode == 1
    assert "FAIL  mod-rewrite-in-use" in r.stdout


def test_check_record_fails_an_empty_list_without_a_reading(tmp_path):
    data = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
    data["expected"]["preconditions"] = []
    data["expected"]["notes"] = "nothing to say"
    bad = tmp_path / "CVE-2024-38475.yaml"
    bad.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    r = _check(bad)
    assert r.returncode == 1 and "(empty list)" in r.stdout


def test_cvelist_text_helper_appends_configurations_when_the_cna_filled_them():
    """cve_text.py relies on the pipeline helper; pin what it does with a filled container."""
    from fetch_sources import cvelist_text

    rec = {"containers": {"cna": {
        "providerMetadata": {"shortName": "palo_alto"},
        "descriptions": [{"lang": "en", "value": "A flaw."}],
        "configurations": [{"lang": "en", "value": "Only when feature X is enabled."}],
    }}}
    text, cna, has_conf, has_work = cvelist_text(rec)
    assert cna == "palo_alto" and has_conf and not has_work
    assert text.startswith("A flaw.") and "Configurations (stated by the CNA):" in text
    assert "Only when feature X is enabled." in text


def test_tools_print_usage_without_arguments():
    for name in ("cve_text.py", "extract_one.py", "check_record.py"):
        r = subprocess.run([sys.executable, str(TOOLS / name)], capture_output=True, text=True)
        assert r.returncode == 2, name
        assert "usage" in (r.stdout + r.stderr).lower() or "Step" in (r.stdout + r.stderr), name


# ── the --input substitution guard (ported from the work rebuild, 2026-09-08) ──────────────
# A model that writes the YAML itself types its own advisory_text; without substitution the
# checker validates citations against that copy. The paraphrase fixture is internally
# consistent (its cites are copied from its own paraphrased text) so it PASSES without
# --input and must FAIL once the captured text is substituted. Guard proven: with
# substitute() made a no-op, test_paraphrase_fails_with_input goes red.

PARA = PKG / "tests" / "fixtures" / "paraphrase"


def _check_with(path: Path, input_path: Path | None):
    argv = [sys.executable, str(TOOLS / "check_record.py"), str(path)]
    if input_path:
        argv += ["--input", str(input_path)]
    return subprocess.run(argv, capture_output=True, text=True)


def test_paraphrase_passes_without_input_but_warns():
    r = _check_with(PARA / "CVE-2024-38475.paraphrase.yaml", None)
    assert r.returncode == 0 and "ACCEPTED" in r.stdout
    assert "WARNING: advisory_text not substituted from capture" in r.stdout


def test_paraphrase_fails_with_input():
    r = _check_with(PARA / "CVE-2024-38475.paraphrase.yaml", PARA / "CVE-2024-38475.input.json")
    assert r.returncode == 1 and "REJECTED" in r.stdout
    assert "TEXT SUBSTITUTED FROM CAPTURE" in r.stdout
    assert "FAIL  mod-rewrite-in-use" in r.stdout
    assert "WARNING" not in r.stdout


def test_reference_passes_with_input():
    r = _check_with(REFERENCE, PARA / "CVE-2024-38475.input.json")
    assert r.returncode == 0 and "TEXT SUBSTITUTED FROM CAPTURE" in r.stdout and "ACCEPTED" in r.stdout


def test_input_without_the_cve_is_an_error(tmp_path):
    cap = tmp_path / "other.input.json"
    cap.write_text('{"CVE-2000-0001": {"text": "x", "source": "cvelist", "source_url": "https://x", "retrieved": "2026-01-01"}}')
    r = _check_with(REFERENCE, cap)
    assert r.returncode == 1 and "CAPTURE FAIL" in r.stdout


# ── the output shape must show the remediation-note keys (found 2026-09-08) ───────────────
# GPT-5.x (M365 Copilot) twice wrote the note's wording under `sentence`; the prompt showed
# `remediation_notes: []` with no item layout and the rules say "each note with its sentence".
# The schema allows only `category` and `text`, so the prompt must show them.

def test_prompt_output_shape_names_the_remediation_note_keys():
    from extract import build_prompt

    prompt = build_prompt("CVE-0000-0000", {"source": "s", "source_url": "u", "retrieved": "d", "text": "t"}, "RULES")
    shape = prompt[prompt.index("Output shape:"):]
    assert "remediation_notes:\n  - category: vendor_fix | workaround | mitigation | none_available | no_fix_planned\n    text: ..." in shape
    assert "sentence" not in shape
