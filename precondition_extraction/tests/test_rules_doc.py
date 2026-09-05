"""RULES.md is the frozen prompt, restated for people. It must not drift from PROMPT.md.

PROMPT.md's sha256 is pinned by test_heldout.py (a rule edit invalidates the held-out number).
RULES.md quotes the rules block verbatim so someone can rebuild the extraction elsewhere from
the document alone; this test is what makes "verbatim" true.
"""
from __future__ import annotations

from pathlib import Path

EVAL = Path(__file__).resolve().parents[1] / "evaluation"


def _rules_block() -> str:
    prompt = (EVAL / "PROMPT.md").read_text(encoding="utf-8")
    start = prompt.index("Rules:")
    end = prompt.index("Here is the advisory")
    return prompt[start:end].rstrip() + "\n"


def test_rules_doc_quotes_the_frozen_prompt_verbatim():
    doc = (EVAL / "RULES.md").read_text(encoding="utf-8")
    block = _rules_block()
    assert block in doc, "RULES.md no longer contains PROMPT.md's rules block verbatim — regenerate it"
    for n in range(1, 11):
        assert f"\n{n}. " in block, f"rule {n} missing from the frozen block"


def test_rules_doc_states_the_unproven_parts():
    doc = (EVAL / "RULES.md").read_text(encoding="utf-8")
    assert "human-reader comparison has not been done" in doc
    assert "not assessed" in doc
