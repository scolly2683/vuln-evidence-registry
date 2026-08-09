"""Run every regression fixture against the shipped registry.

This is the anti-decay gate: each fixture is a past misroute (or a guarded
default) frozen as a test. A rule change that re-breaks any of them fails CI.
"""

from pathlib import Path

import pytest
import yaml

from routing_registry import load_registry, route_finding

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = yaml.safe_load((ROOT / "fixtures" / "regression.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def registry():
    return load_registry(ROOT / "registry")


def test_fixtures_exist():
    assert FIXTURES, "fixtures/regression.yaml is empty — the anti-decay gate is disarmed"


@pytest.mark.parametrize("case", FIXTURES, ids=[c["name"] for c in FIXTURES])
def test_fixture(case, registry):
    result = route_finding(case["finding"], registry)
    expect = case["expect"]
    assert result.disposition == expect["disposition"], (
        f"{case['name']}: expected {expect['disposition']}, got {result.disposition} "
        f"(rule {result.rule_id})"
    )
    if "channel" in expect:
        assert result.channel == expect["channel"], (
            f"{case['name']}: expected channel {expect['channel']}, got {result.channel} "
            f"(rule {result.rule_id})"
        )
    if "rule_id" in expect:
        assert result.rule_id == expect["rule_id"]


def test_shipped_registry_loads_clean(registry):
    # Seed corrections carry future review_by dates at ship time; the loader
    # may still warn (e.g. style warnings) but must not error.
    assert registry.channels
    assert registry.rules_of_kind("identity")
    assert registry.rules_of_kind("screen")
