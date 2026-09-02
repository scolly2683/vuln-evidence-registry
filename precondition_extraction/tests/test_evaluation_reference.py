"""The 50-record KEV evaluation set (precondition_extraction/evaluation/reference/).

These are the hand-verified, citation-checked records the 2026-09 evaluation
scored Haiku 4.5 and Sonnet 5 against. They must always validate against the
fixture schema, every precondition must carry a verbatim citation, and the
citation must be a substring of the advisory text — otherwise the set stops
being a regression gate and becomes a guess.
"""
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from precondition_extraction.schema import citation_in_text, iter_fixtures, validate_fixture

EVAL_DIR = Path(__file__).resolve().parents[1] / "evaluation"
REFERENCE_DIR = EVAL_DIR / "reference"
CANDIDATE_DIRS = ["haiku", "sonnet", "sonnet-r8", "nvd-microsoft"]


def test_reference_set_is_complete_and_valid():
    fixtures = iter_fixtures(REFERENCE_DIR)  # load_fixture validates each one
    assert len(fixtures) == 50


def test_every_reference_precondition_is_cited():
    for path, data in iter_fixtures(REFERENCE_DIR):
        for cond in data["expected"]["preconditions"]:
            assert cond.get("cites"), f"{path.name}: {cond['id']} has no citation"
            assert citation_in_text(cond["cites"], data["advisory_text"]), (
                f"{path.name}: {cond['id']} cites a sentence not in the advisory"
            )


def test_empty_reference_records_state_their_reading():
    """Rule 5: an empty list is a claim with two readings; the notes must say which."""
    for path, data in iter_fixtures(REFERENCE_DIR):
        if not data["expected"]["preconditions"]:
            notes = str(data["expected"].get("notes") or "")
            assert notes.startswith(("genuinely nothing gates this", "this text states no precondition")), (
                f"{path.name}: empty preconditions without the prescribed reading"
            )


def test_microsoft_records_use_msrc_text_where_it_exists():
    """The source finding: NVD is title-only for MSRC CVEs. 12 of the 16
    Microsoft-vendor records were re-sourced from the Security Update Guide."""
    sources = {data["cve_id"]: data["source"] for _, data in iter_fixtures(REFERENCE_DIR)}
    assert sources["CVE-2024-21413"] == "msrc"
    assert sources["CVE-2023-21529"] == "msrc"
    assert sum(1 for s in sources.values() if s == "msrc") == 12


@pytest.mark.parametrize("name", CANDIDATE_DIRS)
def test_candidate_runs_are_present_and_parse(name):
    """Candidate runs are evidence, not fixtures: they must load, not validate
    (a candidate that violates the schema is itself a finding)."""
    files = sorted((EVAL_DIR / "candidates" / name).glob("CVE-*.yaml"))
    assert len(files) == (16 if name == "nvd-microsoft" else 50)
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data["cve_id"] == path.stem


def test_reference_scores_perfectly_against_itself():
    """compare.py's sanity check: the scorer keyed on cited sentences must
    return 1.0 everywhere when a run is compared with itself."""
    import subprocess

    result = subprocess.run(
        [sys.executable, str(EVAL_DIR / "compare.py"), "--cand", "reference"],
        capture_output=True, text=True, cwd=EVAL_DIR,
    )
    assert result.returncode == 0, result.stdout[-2000:]
    assert "| **all** | 50 | 72 | 72 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0 | 0 |" in result.stdout
