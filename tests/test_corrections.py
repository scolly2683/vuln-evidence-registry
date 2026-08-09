"""Tests for the append-on-misroute workflow."""

import datetime as dt
import shutil
from pathlib import Path

import pytest
import yaml

from routing_registry import load_registry, propose_correction, route_finding
from routing_registry.loader import RegistryError

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def registry_copy(tmp_path):
    """A throwaway copy of the shipped registry + fixtures."""
    reg = tmp_path / "registry"
    shutil.copytree(ROOT / "registry", reg)
    shutil.copytree(ROOT / "fixtures", tmp_path / "fixtures")
    return reg


def test_propose_appends_and_routes(registry_copy):
    finding = {
        "id": "f-sp-001",
        "cve_id": "CVE-2026-90020",
        "vendor": "Microsoft",
        "product": "SharePoint Server",
        "description": "RCE in SharePoint Server.",
        "context": {"bundle_member": False},
    }
    rule_id = propose_correction(
        registry_copy,
        route="euc-user-installed",
        match={"vendor": ["microsoft"], "keywords": ["sharepoint"]},
        context={"bundle_member": False},
        decided_by="tester",
        trigger="central bundle does not package SharePoint",
        review_by="2027-02-01",
        fixture_finding=finding,
        today=dt.date(2026, 8, 9),
    )
    assert rule_id.startswith("corr-20260809-")

    registry = load_registry(registry_copy, today=dt.date(2026, 8, 9))
    result = route_finding(finding, registry)
    assert (result.channel, result.rule_id) == ("euc-user-installed", rule_id)

    # Identity default is untouched for findings without the context.
    no_ctx = dict(finding)
    no_ctx.pop("context")
    assert route_finding(no_ctx, registry).channel == "euc-central-bundle"

    # Regression fixture landed alongside.
    fixtures = yaml.safe_load(
        (registry_copy.parent / "fixtures" / "regression.yaml").read_text(encoding="utf-8")
    )
    added = [f for f in fixtures if f["name"] == rule_id]
    assert added and added[0]["expect"]["channel"] == "euc-user-installed"


def test_append_preserves_existing_file_bytes(registry_copy):
    corrections = registry_copy / "rules" / "corrections.yaml"
    before = corrections.read_text(encoding="utf-8")
    propose_correction(
        registry_copy,
        route="middleware",
        match={"keywords": ["nginx"]},
        context={"image_layer": "host"},
        decided_by="tester",
        trigger="test append",
        today=dt.date(2026, 8, 9),
    )
    after = corrections.read_text(encoding="utf-8")
    assert after.startswith(before), "append must not rewrite existing content"


def test_correction_requires_context():
    with pytest.raises(ValueError, match="context predicate"):
        propose_correction(
            ROOT / "registry",
            route="middleware",
            match={"keywords": ["nginx"]},
            context={},
            decided_by="tester",
            trigger="nope",
        )


def test_bad_route_rolls_back(registry_copy):
    corrections = registry_copy / "rules" / "corrections.yaml"
    before = corrections.read_text(encoding="utf-8")
    with pytest.raises(RegistryError):
        propose_correction(
            registry_copy,
            route="no-such-channel",
            match={"keywords": ["nginx"]},
            context={"image_layer": "host"},
            decided_by="tester",
            trigger="bad route",
            today=dt.date(2026, 8, 9),
        )
    assert corrections.read_text(encoding="utf-8") == before


def test_stale_review_by_warns(registry_copy):
    propose_correction(
        registry_copy,
        route="middleware",
        match={"keywords": ["nginx"]},
        context={"image_layer": "host"},
        decided_by="tester",
        trigger="volatile fact",
        review_by="2026-01-01",
        today=dt.date(2026, 8, 9),
    )
    registry = load_registry(registry_copy, today=dt.date(2026, 8, 9))
    assert any("review_by 2026-01-01 has passed" in w for w in registry.warnings)
