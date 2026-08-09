"""Unit tests for routing semantics, against a synthetic in-memory registry."""

import pytest

from routing_registry.models import Channel, Registry, Rule
from routing_registry.router import route_finding, stats


def _registry(rules):
    channels = {
        cid: Channel(id=cid, name=cid)
        for cid in ("chan-a", "chan-b", "chan-c")
    }
    return Registry(channels=channels, rules=rules)


def test_identity_vendor_match_is_case_insensitive_and_containing():
    reg = _registry([Rule(id="r1", kind="identity", match={"vendor": ["red hat"]}, route="chan-a")])
    result = route_finding({"id": "f1", "cve_id": "c1", "vendor": "Red Hat, Inc."}, reg)
    assert result.disposition == "routed"
    assert result.channel == "chan-a"
    assert result.rule_id == "r1"


def test_keywords_match_across_product_package_description():
    reg = _registry([Rule(id="r1", kind="identity", match={"keywords": ["tomcat"]}, route="chan-a")])
    assert route_finding({"id": "f", "cve_id": "c", "description": "Apache Tomcat flaw"}, reg).channel == "chan-a"
    assert route_finding({"id": "f", "cve_id": "c", "package": "tomcat-embed"}, reg).channel == "chan-a"
    assert route_finding({"id": "f", "cve_id": "c", "description": "nginx flaw"}, reg).disposition == "unroutable"


def test_purl_prefix_match():
    reg = _registry([Rule(id="r1", kind="identity", match={"purl_prefix": ["pkg:npm/"]}, route="chan-a")])
    assert route_finding({"id": "f", "cve_id": "c", "purl": "pkg:npm/lodash@4.17.20"}, reg).channel == "chan-a"
    assert route_finding({"id": "f", "cve_id": "c", "purl": "pkg:pypi/x@1"}, reg).disposition == "unroutable"
    assert route_finding({"id": "f", "cve_id": "c"}, reg).disposition == "unroutable"


def test_all_match_predicates_must_hold():
    reg = _registry([
        Rule(id="r1", kind="identity",
             match={"vendor": ["microsoft"], "keywords": ["windows"]}, route="chan-a"),
    ])
    assert route_finding(
        {"id": "f", "cve_id": "c", "vendor": "Microsoft", "product": "Windows 11"}, reg
    ).channel == "chan-a"
    assert route_finding(
        {"id": "f", "cve_id": "c", "vendor": "Microsoft", "product": "SQL Server"}, reg
    ).disposition == "unroutable"


def test_priority_orders_rules_within_a_kind():
    reg = _registry([
        Rule(id="late", kind="identity", priority=50, match={"vendor": ["acme"]}, route="chan-b"),
        Rule(id="early", kind="identity", priority=10, match={"vendor": ["acme"]}, route="chan-a"),
    ])
    result = route_finding({"id": "f", "cve_id": "c", "vendor": "Acme"}, reg)
    assert (result.rule_id, result.channel) == ("early", "chan-a")


def test_correction_overrides_identity():
    reg = _registry([
        Rule(id="ident", kind="identity", match={"keywords": ["tomcat"]}, route="chan-a"),
        Rule(id="corr", kind="correction", match={"keywords": ["tomcat"]},
             context={"image_layer": "base"}, route="chan-b",
             provenance={"date": "2026-08-09", "decided_by": "t", "trigger": "t"}),
    ])
    with_ctx = route_finding(
        {"id": "f", "cve_id": "c", "product": "Tomcat", "context": {"image_layer": "base"}}, reg
    )
    assert (with_ctx.stage, with_ctx.channel) == ("correction", "chan-b")
    without_ctx = route_finding({"id": "f", "cve_id": "c", "product": "Tomcat"}, reg)
    assert (without_ctx.stage, without_ctx.channel) == ("identity", "chan-a")


def test_absent_context_key_never_satisfies_a_predicate():
    reg = _registry([
        Rule(id="corr", kind="correction", match={"keywords": ["tomcat"]},
             context={"image_layer": "base"}, route="chan-b",
             provenance={"date": "2026-08-09", "decided_by": "t", "trigger": "t"}),
    ])
    result = route_finding(
        {"id": "f", "cve_id": "c", "product": "Tomcat", "context": {"other_key": "base"}}, reg
    )
    assert result.disposition == "unroutable"


def test_context_in_and_not_operators():
    reg = _registry([
        Rule(id="corr-in", kind="correction", match={"keywords": ["x"]},
             context={"os_family": {"in": ["macos", "ios"]}}, route="chan-a",
             provenance={"date": "d", "decided_by": "t", "trigger": "t"}),
        Rule(id="corr-not", kind="correction", match={"keywords": ["y"]},
             context={"managed": {"not": True}}, route="chan-b",
             provenance={"date": "d", "decided_by": "t", "trigger": "t"}),
    ])
    assert route_finding(
        {"id": "f", "cve_id": "c", "product": "x", "context": {"os_family": "macos"}}, reg
    ).channel == "chan-a"
    assert route_finding(
        {"id": "f", "cve_id": "c", "product": "x", "context": {"os_family": "windows"}}, reg
    ).disposition == "unroutable"
    assert route_finding(
        {"id": "f", "cve_id": "c", "product": "y", "context": {"managed": False}}, reg
    ).channel == "chan-b"
    assert route_finding(
        {"id": "f", "cve_id": "c", "product": "y", "context": {"managed": True}}, reg
    ).disposition == "unroutable"


def test_screen_fires_before_everything():
    reg = _registry([
        Rule(id="scr", kind="screen", match={"nvd_status": ["Rejected"]}, action="drop"),
        Rule(id="ident", kind="identity", match={"keywords": ["tomcat"]}, route="chan-a"),
    ])
    result = route_finding(
        {"id": "f", "cve_id": "c", "product": "Tomcat", "nvd_status": "Rejected"}, reg
    )
    assert (result.disposition, result.stage) == ("screened", "screen")


def test_park_carries_queue():
    reg = _registry([
        Rule(id="scr", kind="screen", match={"cna": ["VulnCheck"]}, action="park", queue="bulk"),
    ])
    result = route_finding({"id": "f", "cve_id": "c", "cna": "VulnCheck"}, reg)
    assert (result.disposition, result.queue) == ("screened", "bulk")


def test_stats_unroutable_pct():
    reg = _registry([Rule(id="r1", kind="identity", match={"vendor": ["acme"]}, route="chan-a")])
    results = [
        route_finding({"id": "f1", "cve_id": "c", "vendor": "acme"}, reg),
        route_finding({"id": "f2", "cve_id": "c", "vendor": "acme"}, reg),
        route_finding({"id": "f3", "cve_id": "c", "vendor": "other"}, reg),
        route_finding({"id": "f4", "cve_id": "c", "vendor": "other"}, reg),
    ]
    summary = stats(results)
    assert summary["total"] == 4
    assert summary["routed"] == 2
    assert summary["unroutable"] == 2
    assert summary["unroutable_pct"] == pytest.approx(50.0)
    assert summary["by_channel"] == {"chan-a": 2}
