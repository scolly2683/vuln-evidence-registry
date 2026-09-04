"""The held-out evaluation set (precondition_extraction/evaluation/heldout/).

What makes a held-out number believable is a short list of mechanical facts, and
this file pins each one:

  - the draw does not overlap the development set (the 50 reference records) or
    the 170-CVE edge run the extractor already produced output for;
  - the rules were frozen at the draw — PROMPT.md's sha256 still matches
    RULES_FROZEN.json, so a rule edit after the draw fails here, loudly;
  - every worksheet span is a verbatim substring of its advisory text, so the
    owner's sentence numbers really are citations;
  - the model that answered is recorded from the call, and the pin logic picks
    the main model and not the CLI's Haiku side-call;
  - once the reference exists: 30 records, every gate cited, every record's
    notes name its annotator.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from precondition_extraction.schema import citation_in_text, iter_fixtures  # noqa: E402

PKG = Path(__file__).resolve().parents[1]
EVAL = PKG / "evaluation"
HELD = EVAL / "heldout"
REFERENCE_50 = EVAL / "reference"
SLICE_170 = PKG / "pipeline" / "data" / "slice_edge_2023plus.json"
INPUTS = PKG / "pipeline" / "data" / "inputs.json"

sys.path.insert(0, str(HELD))
sys.path.insert(0, str(PKG / "pipeline"))


def _sample() -> list[dict]:
    return json.loads((HELD / "sample.json").read_text(encoding="utf-8"))


# ── the draw ─────────────────────────────────────────────────────────────────


def test_sample_is_30_with_the_planned_strata():
    s = _sample()
    assert len(s) == 30
    by = {}
    for r in s:
        by[r["stratum"]] = by.get(r["stratum"], 0) + 1
    assert by == {"edge": 12, "microsoft": 9, "oss": 9}
    assert sum(1 for r in s if r["owner"]) == 15
    assert len({r["cve_id"] for r in s}) == 30


def test_sample_does_not_overlap_the_development_set_or_the_edge_run():
    ids = {r["cve_id"] for r in _sample()}
    dev = {p.stem for p in REFERENCE_50.glob("CVE-*.yaml")}
    run = set(json.loads(SLICE_170.read_text()))
    assert not (ids & dev), f"held-out overlaps the reference set: {sorted(ids & dev)}"
    assert not (ids & run), f"held-out overlaps the 170-CVE edge run: {sorted(ids & run)}"


def test_every_sampled_cve_has_advisory_text():
    inputs = json.loads(INPUTS.read_text(encoding="utf-8"))
    for r in _sample():
        assert inputs.get(r["cve_id"], {}).get("text"), f"{r['cve_id']} has no text in inputs.json"


# ── the freeze ───────────────────────────────────────────────────────────────


def test_rules_are_still_the_frozen_rules():
    """A rule edit after the draw invalidates the held-out number. This is the alarm."""
    frozen = json.loads((HELD / "RULES_FROZEN.json").read_text(encoding="utf-8"))
    now = hashlib.sha256((EVAL / "PROMPT.md").read_bytes()).hexdigest()
    assert now == frozen["prompt_md_sha256"], (
        "PROMPT.md changed since the held-out draw. Either revert the rule change, or "
        "accept that the held-out set must be re-drawn — a re-score is not an option."
    )


# ── the worksheets ───────────────────────────────────────────────────────────


def test_worksheet_spans_are_verbatim_substrings():
    from worksheet import spans  # heldout/worksheet.py

    inputs = json.loads(INPUTS.read_text(encoding="utf-8"))
    for r in _sample():
        text = inputs[r["cve_id"]]["text"]
        ss = spans(text)
        assert ss, f"{r['cve_id']}: no spans"
        for s in ss:
            assert s in text
            assert citation_in_text(s, text)


def test_owner_worksheets_exist_for_the_owner_15():
    owner = {r["cve_id"] for r in _sample() if r["owner"]}
    have = {p.stem for p in (HELD / "owner").glob("CVE-*.md")}
    assert owner == have


# ── the pin ──────────────────────────────────────────────────────────────────


def test_resolved_model_ignores_the_haiku_side_call():
    """Shape observed 2026-09-03 from `claude -p --model sonnet --output-format json`:
    the requested model shows 2 uncached input tokens + ~42k in cache fields; the
    Haiku side-call shows ~900 input tokens and no cache. Ranking on inputTokens
    alone names Haiku. Ranking on total-including-cache names the right one."""
    from extract import resolved_model  # pipeline/extract.py

    usage = {
        "claude-haiku-4-5-20251001": {"inputTokens": 897, "outputTokens": 8,
                                      "cacheReadInputTokens": 0, "cacheCreationInputTokens": 0},
        "claude-sonnet-5": {"inputTokens": 2, "outputTokens": 4,
                            "cacheReadInputTokens": 33227, "cacheCreationInputTokens": 9025},
    }
    assert resolved_model(usage) == "claude-sonnet-5"
    assert resolved_model({}) is None
    assert resolved_model(None) is None


# ── the reference, once it exists ────────────────────────────────────────────

_REF = HELD / "reference"
needs_reference = pytest.mark.skipif(
    not _REF.is_dir() or not any(_REF.glob("CVE-*.yaml")),
    reason="held-out reference not built yet (Steps 4-5)",
)


@needs_reference
def test_heldout_reference_is_complete_and_valid():
    fixtures = iter_fixtures(_REF)
    assert len(fixtures) == 30
    assert {p.stem for p, _ in fixtures} == {r["cve_id"] for r in _sample()}


@needs_reference
def test_every_heldout_precondition_is_cited():
    for path, data in iter_fixtures(_REF):
        for cond in data["expected"]["preconditions"]:
            assert cond.get("cites"), f"{path.name}: {cond['id']} has no citation"
            assert citation_in_text(cond["cites"], data["advisory_text"])


@needs_reference
def test_every_heldout_record_names_its_annotator():
    for path, data in iter_fixtures(_REF):
        notes = str(data["expected"].get("notes") or "").lower()
        assert ("owner" in notes and "adjudicat" in notes) or "blind reference build" in notes, (
            f"{path.name}: notes must say whether this is owner-adjudicated or Claude's blind build"
        )


# ── the candidate run, once it exists ────────────────────────────────────────


def test_heldout_candidate_runs_record_a_pinned_model():
    cands = HELD / "candidates"
    if not cands.is_dir():
        pytest.skip("no held-out candidate run yet (Step 6)")
    for run_dir in cands.iterdir():
        meta_path = run_dir / "_run.json"
        assert meta_path.exists(), f"{run_dir.name}: no _run.json"
        meta = json.loads(meta_path.read_text())
        mr = meta.get("model_resolved")
        assert mr and mr.startswith("claude-") and "," not in mr, (
            f"{run_dir.name}: model_resolved={mr!r} — the held-out run must be one pinned model"
        )
        for p in run_dir.glob("CVE-*.yaml"):
            yaml.safe_load(p.read_text(encoding="utf-8"))
