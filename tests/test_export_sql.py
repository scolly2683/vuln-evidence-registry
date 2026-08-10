"""tools/export_registry_sql.py — the YAML→CSV flattener for the SQL twin.

The exporter's contract: everything it emits must be evaluable by the generic
SQL routing view in docs/sql-powerbi.md with the same semantics as
router.py, and anything it cannot faithfully translate must fail loudly.
"""

import csv
import importlib.util
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "export_registry_sql", REPO_ROOT / "tools" / "export_registry_sql.py"
)
export_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(export_mod)


def _read_csv(path):
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture(scope="module")
def exported(tmp_path_factory):
    out = tmp_path_factory.mktemp("export")
    counts = export_mod.export(
        REPO_ROOT / "registry", REPO_ROOT / "fixtures" / "regression.yaml", out
    )
    return out, counts


def test_counts_match_registry(exported):
    out, counts = exported
    from routing_registry.loader import load_registry

    registry = load_registry(REPO_ROOT / "registry")
    assert counts["channels.csv"] == len(registry.channels)
    assert counts["rules.csv"] == len(registry.rules)
    fixtures = yaml.safe_load(
        (REPO_ROOT / "fixtures" / "regression.yaml").read_text(encoding="utf-8")
    )
    assert counts["fixtures.csv"] == len(fixtures)
    assert counts["fixture_findings.csv"] == counts["fixtures.csv"]  # ids unique today


def test_correction_flattens_to_rule_plus_predicates(exported):
    out, _ = exported
    rules = {r["rule_id"]: r for r in _read_csv(out / "rules.csv")}
    rule = rules["corr-20260809-tomcat-base-layer"]
    assert rule["kind"] == "correction"
    assert rule["route_channel_id"] == "platform-rehydrate"
    assert rule["decided_by"] == "dscollan"
    assert rule["review_by"] == "2027-02-01"

    preds = [
        p
        for p in _read_csv(out / "rule_predicates.csv")
        if p["rule_id"] == "corr-20260809-tomcat-base-layer"
    ]
    assert {(p["pred_type"], p["pred_key"], p["pred_value"]) for p in preds} == {
        ("keywords", "", "tomcat"),
        ("context", "image_layer", "base"),
    }


def test_keyword_whitespace_survives_verbatim(exported):
    """' plc ' matches whole words by design; a helpful TRIM would change routing."""
    out, _ = exported
    values = [
        p["pred_value"]
        for p in _read_csv(out / "rule_predicates.csv")
        if p["rule_id"] == "screen-ics-ot" and p["pred_type"] == "keywords"
    ]
    assert " plc " in values


def test_context_booleans_export_lowercase(exported):
    out, _ = exported
    preds = [
        p
        for p in _read_csv(out / "rule_predicates.csv")
        if p["rule_id"] == "corr-20260809-visual-studio-bundle"
        and p["pred_type"] == "context"
    ]
    assert preds == [
        {
            "rule_id": "corr-20260809-visual-studio-bundle",
            "pred_type": "context",
            "pred_key": "bundle_member",
            "pred_value": "false",
        }
    ]


def test_fixture_context_rows_exported(exported):
    out, _ = exported
    rows = _read_csv(out / "fixture_finding_context.csv")
    assert {
        (r["finding_id"], r["context_key"], r["context_value"]) for r in rows
    } >= {("f-vs-001", "bundle_member", "false"), ("f-tc-001", "image_layer", "base")}


def test_screen_park_carries_queue(exported):
    out, _ = exported
    rules = {r["rule_id"]: r for r in _read_csv(out / "rules.csv")}
    assert rules["screen-vulncheck-bulk"]["screen_action"] == "park"
    assert rules["screen-vulncheck-bulk"]["park_queue"] == "bulk-feed-verify"


def test_context_in_operator_flattens_to_or_rows():
    _, preds = export_mod.flatten_rule(
        {
            "id": "corr-x",
            "match": {"keywords": ["tomcat"]},
            "context": {"image_layer": {"in": ["base", "golden"]}},
            "route": "platform-rehydrate",
        },
        "correction",
    )
    context_values = {p["pred_value"] for p in preds if p["pred_type"] == "context"}
    assert context_values == {"base", "golden"}


def test_unsupported_context_operator_fails_loudly():
    with pytest.raises(export_mod.ExportError, match="no SQL translation"):
        export_mod.flatten_rule(
            {
                "id": "corr-x",
                "match": {"keywords": ["tomcat"]},
                "context": {"image_layer": {"not": "base"}},
                "route": "middleware",
            },
            "correction",
        )


def test_unknown_match_field_fails_loudly():
    with pytest.raises(export_mod.ExportError, match="not implemented by the SQL"):
        export_mod.flatten_rule(
            {"id": "id-x", "match": {"cpe": ["cpe:2.3"]}, "route": "middleware"},
            "identity",
        )
