"""tools/sync_suppressions.py — plan and reconcile scanner-side suppressions.

The property that matters most: an identifier suppressed in a tool with no
registry rule behind it is flagged UNMANAGED, and expired registry rules
move identifiers to the remove list instead of hiding them.
"""

import datetime as dt
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "sync_suppressions", REPO_ROOT / "tools" / "sync_suppressions.py"
)
sync_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync_mod)

TODAY = dt.date(2026, 8, 9)


@pytest.fixture(scope="module")
def state():
    return sync_mod.desired_state(REPO_ROOT / "registry", today=TODAY)


def test_plan_covers_seed_suppressions(state):
    # QID cluster + its vex CVE -> synced (no context). The Spring4Shell rule
    # carries a context predicate, so it must NOT be blanket-synced.
    assert state["qualys"] == {
        "376157": "sup-20260809-log4j1-version-match",
        "376178": "sup-20260809-log4j1-version-match",
    }
    assert state["wiz"] == {"CVE-2021-44228": "sup-20260809-log4j1-version-match"}
    assert state["expired"] == {"qualys": {}, "wiz": {}}


def test_context_bearing_suppression_is_not_blanket_synced(state):
    # The config-conditional Spring4Shell verdict must be held back from a
    # blanket scanner mute (it would silence genuinely vulnerable instances).
    assert "CVE-2022-22965" not in state["wiz"]
    scoped = {c["rule_id"] for c in state["context_scoped"]}
    assert "sup-20260809-spring4shell-nonvulnerable-config" in scoped
    entry = next(c for c in state["context_scoped"]
                 if c["rule_id"] == "sup-20260809-spring4shell-nonvulnerable-config")
    assert entry["context"] == {"config_vulnerable": False}
    assert entry["identifiers"]["wiz"] == ["CVE-2022-22965"]


def test_expired_rules_move_to_expired_bucket():
    # Only the context-free log4j rule participates in the sync buckets; past
    # its review_by it moves to expired. The context-bearing Spring4Shell rule
    # is held out of blanket sync entirely (context_scoped), expired or not.
    state = sync_mod.desired_state(REPO_ROOT / "registry", today=dt.date(2028, 1, 1))
    assert state["qualys"] == {} and state["wiz"] == {}
    assert "376157" in state["expired"]["qualys"]
    assert "CVE-2021-44228" in state["expired"]["wiz"]


def test_parse_actual_qualys_uses_qid_column_when_present(tmp_path):
    # With a real QID column, only that column is read — asset ids / ports in
    # other columns must not be mistaken for QIDs.
    export = tmp_path / "qualys.csv"
    export.write_text(
        "QID,AssetID,Port\n376157,900001,8080\n999123,900002,44300\n",
        encoding="utf-8",
    )
    assert sync_mod.parse_actual("qualys", export) == {"376157", "999123"}


def test_parse_actual_qualys_falls_back_to_regex_without_column(tmp_path):
    export = tmp_path / "qualys.txt"
    export.write_text("Excluded QIDs: 376157 376178\n", encoding="utf-8")
    assert sync_mod.parse_actual("qualys", export) == {"376157", "376178"}


def test_parse_actual_wiz_accepts_strings_and_objects(tmp_path):
    export = tmp_path / "wiz.json"
    export.write_text(
        '["cve-2021-44228", {"cve": "CVE-2000-0001"}, {"name": "CVE-2000-0002"},'
        ' {"cves": ["CVE-2000-0003"]}, {"name": "not-a-cve"}]',
        encoding="utf-8",
    )
    assert sync_mod.parse_actual("wiz", export) == {
        "CVE-2021-44228",
        "CVE-2000-0001",
        "CVE-2000-0002",
        "CVE-2000-0003",
    }


def test_reconcile_classifies_all_four_ways(state):
    actual = {"376157", "555555"}  # one managed, one unmanaged; 376178 missing
    diff = sync_mod.reconcile("qualys", actual, state)
    assert diff["managed"] == ["376157"]
    assert diff["missing"] == ["376178"]
    assert diff["unmanaged"] == ["555555"]
    assert diff["expired"] == []


def test_reconcile_flags_expired_as_remove_not_unmanaged():
    state = sync_mod.desired_state(REPO_ROOT / "registry", today=dt.date(2028, 1, 1))
    diff = sync_mod.reconcile("qualys", {"376157"}, state)
    assert diff["expired"] == ["376157"]
    assert diff["unmanaged"] == []


def test_cli_reconcile_exit_codes(tmp_path, capsys):
    clean = tmp_path / "clean.txt"
    clean.write_text("376157 376178\n", encoding="utf-8")
    assert sync_mod.main(
        ["reconcile", "--registry", str(REPO_ROOT / "registry"),
         "--tool", "qualys", "--actual", str(clean)]
    ) == 0

    drift = tmp_path / "drift.txt"
    drift.write_text("376157 555555\n", encoding="utf-8")
    assert sync_mod.main(
        ["reconcile", "--registry", str(REPO_ROOT / "registry"),
         "--tool", "qualys", "--actual", str(drift)]
    ) == 1
    out = capsys.readouterr().out
    assert "UNMANAGED QID 555555" in out
    assert "MISSING   QID 376178" in out
