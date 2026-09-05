"""The CVE-2024-38475 host check (precondition_extraction/checks/CVE-2024-38475/).

A check compiled from a cited precondition is only worth shipping if it is right on the
shapes that matter and says "not assessed" where it cannot know. The fixtures are the
shapes; each has one expected verdict per gate. The positive evidence must be the exact
config line — a verdict without its line is a guess.

Guard proven real on 2026-09-05: with EXPANSION broken to r"^NEVER", 13 of 37 tests fail
(every positive fixture, the coarse-mode test and the predicate unit test); restored, all pass.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

PKG = Path(__file__).resolve().parents[1]
CHECK_DIR = PKG / "checks" / "CVE-2024-38475"
FIXTURES = CHECK_DIR / "fixtures"
SCRIPT = CHECK_DIR / "check_rewrite_prefix.py"
RECORD = PKG / "evaluation" / "reference" / "CVE-2024-38475.yaml"

sys.path.insert(0, str(CHECK_DIR))
from check_rewrite_prefix import (  # noqa: E402
    GATE_FILES, GATE_MODULE, GATE_SUBST, _config_files, scan,
)

EXPECTED = {
    # fixture: (mod-rewrite-in-use, server-context-substitution…, exit code)
    "positive-vhost": ("present", "present", 2),
    "positive-debian": ("present", "present", 2),
    "positive-ups-flag": ("present", "present", 2),
    "negative-directory-context": ("present", "absent", 2),
    "negative-literal-prefix": ("present", "absent", 2),
    "negative-no-rewrite": ("absent", "absent", 0),
    "negative-docroot-anchored": ("present", "absent", 2),
    "positive-rewriteoptions": ("present", "present", 2),
}


def _gates(name: str) -> dict:
    report = scan(list(_config_files(FIXTURES / name)))
    return {g["id"]: g for g in report["gates"]}


def test_every_fixture_has_an_expectation_and_vice_versa():
    assert {p.name for p in FIXTURES.iterdir() if p.is_dir()} == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_verdicts(name):
    g = _gates(name)
    want_module, want_subst, _ = EXPECTED[name]
    assert g[GATE_MODULE]["verdict"] == want_module, g[GATE_MODULE]
    assert g[GATE_SUBST]["verdict"] == want_subst, g[GATE_SUBST]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_gate_three_is_never_decided(name):
    assert _gates(name)[GATE_FILES]["verdict"] == "not_assessed"


@pytest.mark.parametrize("name", [n for n, e in EXPECTED.items() if e[1] == "present"])
def test_positive_evidence_is_the_verbatim_config_line(name):
    g = _gates(name)[GATE_SUBST]
    assert g["evidence"], "present without evidence"
    for ev in g["evidence"]:
        path, line = Path(ev["file"]), ev["line"]
        assert path.read_text(encoding="utf-8").splitlines()[line - 1].rstrip() == ev["text"]
        assert ev.get("context", "server") == "server"


def test_directory_context_rule_is_reported_as_ignored_not_hidden():
    g = _gates("negative-directory-context")[GATE_SUBST]
    assert len(g["ignored"]) == 1 and g["ignored"][0]["context"] == "directory"
    assert "directory" in g["ignored"][0]["enclosing"]


def test_docroot_anchored_rule_is_ignored_with_a_reason():
    g = _gates("negative-docroot-anchored")[GATE_SUBST]
    assert g["verdict"] == "absent" and len(g["ignored"]) == 1
    assert "DOCUMENT_ROOT" in g["detail"]


def test_first_segment_rule_matches_the_httpd_fix():
    from check_rewrite_prefix import first_segment_is_expanded as f
    assert f("/$1.css")            # SonicWall SMA 100 (watchTowr)
    assert f("$1")                 # the Apache docs' UnsafePrefixStat example
    assert f("%{ENV:ROOT}/x/$1")   # variable first
    assert f("/foo$1/bar")         # literal+backreference in ONE segment: prefix_stat's startsWith fails
    assert not f("/var/www/$1")    # literal first segment
    assert not f("http://backend.internal/$1")
    assert not f("-")


def test_rewriteoptions_ups_is_reported():
    g = _gates("positive-rewriteoptions")[GATE_SUBST]
    assert "RewriteOptions UnsafePrefixStat" in g["detail"]


def test_ups_flag_is_flagged_as_opted_back_in():
    g = _gates("positive-ups-flag")[GATE_SUBST]
    assert g["evidence"][0]["opted_back_in"] is True
    assert "UnsafePrefixStat" in g["detail"]


def test_coarse_mode_is_what_a_single_regex_sees():
    """A vendor rule with no block tracking would flag the directory-context fixture."""
    report = scan(list(_config_files(FIXTURES / "negative-directory-context")), coarse=True)
    g = {x["id"]: x for x in report["gates"]}[GATE_SUBST]
    assert g["verdict"] == "present" and "COARSE" in g["detail"]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_cli_json_and_exit_code(name):
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(FIXTURES / name)],
                       capture_output=True, text=True)
    assert r.returncode == EXPECTED[name][2], r.stderr
    report = json.loads(r.stdout)
    assert report["cve_id"] == "CVE-2024-38475"
    assert [g["id"] for g in report["gates"]] == [GATE_MODULE, GATE_SUBST, GATE_FILES]


def test_dump_includes_input(tmp_path):
    files = sorted(_config_files(FIXTURES / "positive-debian"))
    dump = tmp_path / "dump.txt"
    dump.write_text("Included configuration files:\n" + "".join(f"  ({i}) {p}\n" for i, p in enumerate(files)))
    r = subprocess.run([sys.executable, str(SCRIPT), "--dump-includes", str(dump), "--format", "text"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "PRESENT" in r.stdout


def test_gate_ids_match_the_record():
    """The check is keyed by the record's precondition ids; if the record is re-verified and an
    id changes, this is what says the check must follow."""
    rec = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    ids = {c["id"] for c in rec["expected"]["preconditions"]}
    assert {GATE_MODULE, GATE_SUBST, GATE_FILES} == ids
