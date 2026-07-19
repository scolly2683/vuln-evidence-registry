"""evidence_sources.py — a declarative registry of exploitation-evidence sources.

A common failure mode in vulnerability-prioritisation pipelines: the same
"is this signal high-priority?" decision gets hand-wired in two places — once as
a SQL gate over the whole corpus (for bulk/batch selection) and once as a
per-record Python predicate (for on-the-fly evaluation). They drift. A new
evidence source gets ingested into a table but someone forgets to add it to the
gate SQL, so it's stored but never actually gates anything.

This module fixes that by making **one declarative registry** the single source
of truth for both. Each :class:`EvidenceSource` carries:

  (a) a SQL fragment yielding ``cve_id`` rows — UNION-composed into a single gate
      query so the whole gate stays one round-trip, and
  (b) a pure-Python predicate twin — the same rule, evaluated against an
      in-memory :class:`EvidenceContext`.

Add a source once and it flows into the gate SQL, the Python twin, and the
"act-now" escalation set at the same time. There is no second place to update.

Execution shape is deliberately fixed: a gate leg must be expressible as SQL over
already-ingested data plus a pure predicate. Arbitrary per-record async lookups
are NOT allowed as gate legs — a source that needs a live external call must
ingest into a table/column first, then gate on that.

Categories
----------
``known_exploited`` — something observed/confirmed this vulnerability being
    exploited (KEV of any provenance, sensor networks, vendor "exploited in the
    wild", SSVC exploitation=active). These are the act-now-eligible set.
``poc``             — a public proof-of-concept exists (capability, not evidence
                      of use).
``predicted``       — a forecast of near-term exploitation (e.g. EPSS).
``severity``        — blast-radius / automatability with NO exploitation evidence.
                      Gates enrichment so high-impact items aren't dropped, but is
                      NOT act-now-eligible — this keeps well-engineered,
                      never-targeted items out of an "act now" queue.

The SQL fragments below reference example table/column names (``kev_entries``,
``poc_refs``, ``cves.greynoise_observed``, …) to keep the example concrete; adapt
them to your own schema. The *pattern* — one registry, two composed outputs — is
the point.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

# EPSS threshold for the general high-signal gate.
EPSS_THRESHOLD = 0.10

# EPSS level at which a KNOWN-exploited item is escalated to the "act now" tier.
ACT_NOW_EPSS_THRESHOLD = 0.30


@dataclass(frozen=True)
class EvidenceContext:
    """Per-record facts consumed by the pure-Python predicate twins."""

    epss_score: float | None = None
    in_kev: bool = False
    has_poc: bool = False
    msrc_exploited: bool = False
    ssvc_exploitation: str | None = None
    ssvc_automatable: str | None = None
    ssvc_technical_impact: str | None = None
    greynoise_observed: bool = False
    vulncheck_kev: bool = False
    circl_shadowserver_kev: bool = False
    epss_threshold: float = EPSS_THRESHOLD


@dataclass(frozen=True)
class EvidenceSource:
    """One exploitation-evidence source — see module docstring."""

    key: str
    category: str  # known_exploited | poc | predicted | severity
    label: str
    # A SQL SELECT yielding a ``cve_id`` column, ending in a WHERE predicate so
    # the composer can append an id-scoping ``AND`` clause. ``None`` id_column
    # means the fragment is already id-scoped by an enclosing CTE (EPSS reads
    # the scoped ``latest_epss`` CTE), so no clause is appended.
    raw_sql: str
    id_column: str | None
    py_predicate: Callable[[EvidenceContext], bool]
    gates_high_signal: bool = True
    act_now_eligible: bool = False


# ── The registry ──────────────────────────────────────────────────────────────
# Order is presentational only; membership/flags drive everything.

REGISTRY: tuple[EvidenceSource, ...] = (
    EvidenceSource(
        key="cisa_kev",
        category="known_exploited",
        label="CISA KEV",
        raw_sql="SELECT DISTINCT cve_id FROM kev_entries WHERE TRUE",
        id_column="cve_id",
        py_predicate=lambda c: c.in_kev,
        act_now_eligible=True,
    ),
    EvidenceSource(
        key="vulncheck_kev",
        category="known_exploited",
        label="VulnCheck KEV",
        raw_sql="SELECT id AS cve_id FROM cves WHERE vulncheck_kev = TRUE",
        id_column="id",
        py_predicate=lambda c: c.vulncheck_kev,
        act_now_eligible=True,
    ),
    EvidenceSource(
        # A classic "ingested but never gated" case: a source that lands in a
        # table but is forgotten in the hand-wired gate SQL. In a registry it
        # cannot be forgotten — membership here IS the gate.
        key="circl_shadowserver_kev",
        category="known_exploited",
        label="CIRCL/Shadowserver honeypot KEV",
        raw_sql=(
            "SELECT DISTINCT cve_id FROM kev_assertions "
            "WHERE source = 'circl_shadowserver_kev'"
        ),
        id_column="cve_id",
        py_predicate=lambda c: c.circl_shadowserver_kev,
        act_now_eligible=True,
    ),
    EvidenceSource(
        key="greynoise_observed",
        category="known_exploited",
        label="GreyNoise observed exploitation",
        raw_sql="SELECT id AS cve_id FROM cves WHERE greynoise_observed = TRUE",
        id_column="id",
        py_predicate=lambda c: c.greynoise_observed,
        act_now_eligible=True,
    ),
    EvidenceSource(
        key="msrc_exploited",
        category="known_exploited",
        label="MSRC exploited in the wild",
        raw_sql=(
            "SELECT DISTINCT cve_id FROM msrc_patches "
            "WHERE exploited_in_wild = true AND cve_id IS NOT NULL"
        ),
        id_column="cve_id",
        py_predicate=lambda c: c.msrc_exploited,
        act_now_eligible=True,
    ),
    EvidenceSource(
        # CISA-published SSVC decision point only (columns are NULL unless
        # published — derived/worst-case values must never gate).
        key="ssvc_active",
        category="known_exploited",
        label="CISA SSVC exploitation=active",
        raw_sql="SELECT id AS cve_id FROM cves WHERE ssvc_exploitation = 'active'",
        id_column="id",
        py_predicate=lambda c: c.ssvc_exploitation == "active",
        act_now_eligible=True,
    ),
    EvidenceSource(
        key="public_poc",
        category="poc",
        label="Public PoC available",
        raw_sql="SELECT DISTINCT cve_id FROM poc_refs WHERE TRUE",
        id_column="cve_id",
        py_predicate=lambda c: c.has_poc,
        act_now_eligible=False,
    ),
    EvidenceSource(
        # Reads the enclosing scoped ``latest_epss`` CTE, so no id clause.
        key="epss",
        category="predicted",
        label="EPSS above gate threshold",
        raw_sql="SELECT cve_id FROM latest_epss WHERE score >= :threshold",
        id_column=None,
        py_predicate=lambda c: (
            c.epss_score is not None and float(c.epss_score) >= c.epss_threshold
        ),
        act_now_eligible=False,
    ),
    EvidenceSource(
        # High blast-radius (automatable + total impact) with NO exploitation
        # evidence. Kept in the gate so these items are still enriched — but NOT
        # act_now_eligible, which is what stops well-engineered, never-targeted
        # items from polluting an "act now" queue.
        key="ssvc_automatable_total",
        category="severity",
        label="SSVC automatable + total impact",
        raw_sql=(
            "SELECT id AS cve_id FROM cves "
            "WHERE ssvc_automatable = 'yes' AND ssvc_technical_impact = 'total'"
        ),
        id_column="id",
        py_predicate=lambda c: (
            c.ssvc_automatable == "yes" and c.ssvc_technical_impact == "total"
        ),
        act_now_eligible=False,
    ),
)


# ── Composition helpers ───────────────────────────────────────────────────────


def _union_sql(sources: tuple[EvidenceSource, ...], scoped: bool) -> str:
    """UNION the fragments of ``sources`` into one ``cve_id``-yielding body.

    When ``scoped`` is True, an ``AND <id_column> = ANY(CAST(:ids AS text[]))``
    clause is appended to every fragment that carries an ``id_column`` (EPSS is
    already scoped via ``latest_epss`` and is left untouched).
    """
    parts: list[str] = []
    for s in sources:
        frag = s.raw_sql
        if scoped and s.id_column:
            frag = f"{frag} AND {s.id_column} = ANY(CAST(:ids AS text[]))"
        parts.append(frag)
    return "\n            UNION\n            ".join(parts)


def gate_union_sql(scoped: bool) -> str:
    """UNION body of every ``gates_high_signal`` source — the high-signal gate."""
    return _union_sql(
        tuple(s for s in REGISTRY if s.gates_high_signal), scoped
    )


def act_now_union_sql(scoped: bool) -> str:
    """UNION body of every ``act_now_eligible`` source — the known-exploited set
    that (with EPSS>=0.30) escalates a high-signal item to the ``act_now`` tier."""
    return _union_sql(
        tuple(s for s in REGISTRY if s.act_now_eligible), scoped
    )


def evaluate_gate(ctx: EvidenceContext) -> bool:
    """Pure-Python high-signal decision — the SQL twin, driven by the same
    registry so the two can never drift."""
    return any(
        s.py_predicate(ctx) for s in REGISTRY if s.gates_high_signal
    )
