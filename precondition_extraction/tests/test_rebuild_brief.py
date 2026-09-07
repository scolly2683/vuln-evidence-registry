"""The rebuild brief (docs/precondition-tool-REBUILD-BRIEF.txt) must be regenerable and exact.

A brief that drifts from the rules or the schema would let a rebuilt tool disagree with this
one while claiming the same standard. These tests pin: the committed brief equals what the
generator produces now; the rules block and schema.json are in it verbatim; no repository
identifiers leak into a document meant for a work tool; the parts concatenate to the whole.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
DOCS = PKG / "docs"
BRIEF = DOCS / "precondition-tool-REBUILD-BRIEF.txt"
GEN = PKG / "tools" / "build_rebuild_brief.py"

sys.path.insert(0, str(PKG / "tools"))


def test_committed_brief_matches_the_generator(tmp_path):
    import build_rebuild_brief as b

    assert BRIEF.exists(), "run tools/build_rebuild_brief.py"
    assert BRIEF.read_text(encoding="utf-8") == b.build()


def test_brief_carries_rules_and_schema_verbatim():
    import build_rebuild_brief as b

    text = BRIEF.read_text(encoding="utf-8")
    assert b.rules_block() in text
    assert b.embedded_schema().rstrip() in text
    # the embedded schema is the real schema minus only its "$id" line
    real = json.loads((PKG / "tests" / "fixtures" / "schema.json").read_text(encoding="utf-8"))
    real.pop("$id", None)
    assert json.loads(b.embedded_schema()) == real
    # the schema embedded must still be valid JSON as embedded
    start = text.index("<<<SCHEMA_BEGIN>>>") + len("<<<SCHEMA_BEGIN>>>")
    end = text.index("<<<SCHEMA_END>>>")
    json.loads(text[start:end])


def test_brief_has_no_repository_identifiers():
    text = BRIEF.read_text(encoding="utf-8")
    for banned in ("github.com/scolly2683", "scolly2683", "vuln-evidence-registry"):
        assert banned not in text


def test_parts_concatenate_to_the_whole():
    import build_rebuild_brief as b

    whole = BRIEF.read_text(encoding="utf-8")
    joined = ""
    for i in range(1, b.PARTS + 1):
        p = (DOCS / f"precondition-tool-REBUILD-BRIEF-part{i}of{b.PARTS}.txt").read_text(encoding="utf-8")
        head, _, body = p.partition("\n\n")
        assert head.startswith(f"[PART {i} OF {b.PARTS}")
        joined += body
    assert joined == whole


def test_generator_runs_clean():
    r = subprocess.run([sys.executable, str(GEN)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "wrote" in r.stdout
