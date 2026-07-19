"""Tests for the declarative evidence-source registry.

These demonstrate the core promise of the pattern: the SQL gate and the
pure-Python predicate twin are both composed from ONE registry, so they can't
drift, and the "act now" set is a strict, well-defined subset of the gate.
"""
from vuln_evidence_registry.evidence_sources import (
    ACT_NOW_EPSS_THRESHOLD,
    EPSS_THRESHOLD,
    REGISTRY,
    EvidenceContext,
    act_now_union_sql,
    evaluate_gate,
    gate_union_sql,
)

VALID_CATEGORIES = {"known_exploited", "poc", "predicted", "severity"}


# ── The pure-Python twin (evaluate_gate) ──────────────────────────────────────


def test_kev_gates():
    assert evaluate_gate(EvidenceContext(in_kev=True)) is True


def test_epss_above_threshold_gates_below_does_not():
    assert evaluate_gate(EvidenceContext(epss_score=EPSS_THRESHOLD)) is True
    assert evaluate_gate(EvidenceContext(epss_score=EPSS_THRESHOLD - 0.001)) is False


def test_automatable_total_gates_but_only_together():
    assert evaluate_gate(
        EvidenceContext(ssvc_automatable="yes", ssvc_technical_impact="total")
    ) is True
    assert evaluate_gate(EvidenceContext(ssvc_automatable="yes")) is False


def test_no_evidence_does_not_gate():
    assert evaluate_gate(EvidenceContext()) is False


def test_each_known_exploited_leg_gates_on_its_own():
    for ctx in (
        EvidenceContext(vulncheck_kev=True),
        EvidenceContext(greynoise_observed=True),
        EvidenceContext(circl_shadowserver_kev=True),
        EvidenceContext(msrc_exploited=True),
        EvidenceContext(ssvc_exploitation="active"),
        EvidenceContext(has_poc=True),
    ):
        assert evaluate_gate(ctx) is True


# ── The SQL twin (gate_union_sql / act_now_union_sql) ─────────────────────────


def test_gate_sql_unions_every_gating_source():
    sql = gate_union_sql(scoped=False)
    n_gating = sum(1 for s in REGISTRY if s.gates_high_signal)
    # N sources → N-1 UNION keywords.
    assert sql.count("UNION") == n_gating - 1
    assert "kev_entries" in sql and "poc_refs" in sql and "latest_epss" in sql


def test_scoping_appends_id_clause_to_id_sources_but_not_epss():
    scoped = gate_union_sql(scoped=True)
    # Every id_column source gets an id-scoping clause...
    assert "= ANY(CAST(:ids AS text[]))" in scoped
    # ...but the EPSS leg (id_column=None, already scoped via latest_epss) does not
    # get one appended: its fragment stays exactly as declared.
    assert "FROM latest_epss WHERE score >= :threshold AND" not in scoped
    # Unscoped form has no id clause at all.
    assert "= ANY(CAST(:ids AS text[]))" not in gate_union_sql(scoped=False)


def test_act_now_is_strict_subset_of_gate():
    act_now = tuple(s for s in REGISTRY if s.act_now_eligible)
    gating = tuple(s for s in REGISTRY if s.gates_high_signal)
    assert set(s.key for s in act_now) < set(s.key for s in gating)
    # PoC, EPSS and the automatable+total severity leg gate enrichment but are
    # deliberately NOT act-now-eligible (no exploitation evidence).
    assert {"public_poc", "epss", "ssvc_automatable_total"}.isdisjoint(
        s.key for s in act_now
    )


def test_act_now_sql_only_contains_act_now_sources():
    sql = act_now_union_sql(scoped=False)
    assert "poc_refs" not in sql  # public_poc is not act-now-eligible
    assert "latest_epss" not in sql  # epss is not act-now-eligible
    assert "kev_entries" in sql  # cisa_kev is


# ── Registry invariants ───────────────────────────────────────────────────────


def test_registry_invariants():
    keys = [s.key for s in REGISTRY]
    assert len(keys) == len(set(keys)), "duplicate source keys"
    for s in REGISTRY:
        assert s.category in VALID_CATEGORIES
        # An act-now-eligible source must also gate and must be exploitation evidence.
        if s.act_now_eligible:
            assert s.gates_high_signal
            assert s.category == "known_exploited"


def test_thresholds_are_ordered():
    assert 0.0 < EPSS_THRESHOLD < ACT_NOW_EPSS_THRESHOLD < 1.0
