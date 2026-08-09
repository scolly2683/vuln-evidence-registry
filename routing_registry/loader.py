"""Load and validate a registry directory.

Layout (all YAML files are top-level lists so corrections can be appended
without rewriting the file):

    registry/
      channels.yaml            # list of channel definitions
      screens.yaml             # list of screen rules (pre-channel stage)
      rules/identity.yaml      # list of identity rules
      rules/corrections.yaml   # append-only list of correction rules
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import yaml

from .models import (
    CADENCE_TYPES,
    RULE_KINDS,
    SCREEN_ACTIONS,
    SUBJECT_FIELDS,
    VIRTUAL_MATCHERS,
    Channel,
    Registry,
    Rule,
)


class RegistryError(Exception):
    """Raised when the registry data is structurally invalid."""


def _load_yaml_list(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if not isinstance(data, list):
        raise RegistryError(f"{path}: expected a top-level YAML list, got {type(data).__name__}")
    return data


def _parse_channels(raw: list[dict], errors: list[str]) -> dict[str, Channel]:
    channels: dict[str, Channel] = {}
    for entry in raw:
        cid = entry.get("id")
        if not cid:
            errors.append("channel entry missing id")
            continue
        if cid in channels:
            errors.append(f"duplicate channel id: {cid}")
            continue
        if entry.get("cadence_type", "ad_hoc") not in CADENCE_TYPES:
            errors.append(f"channel {cid}: invalid cadence_type {entry.get('cadence_type')!r}")
        channels[cid] = Channel(
            id=cid,
            name=entry.get("name", cid),
            description=entry.get("description", ""),
            cadence=entry.get("cadence", ""),
            cadence_type=entry.get("cadence_type", "ad_hoc"),
            owner=entry.get("owner", "UNASSIGNED"),
            parent=entry.get("parent"),
        )
    for ch in channels.values():
        if ch.parent and ch.parent not in channels:
            errors.append(f"channel {ch.id}: unknown parent {ch.parent}")
    return channels


def _parse_rules(raw: list[dict], kind: str, errors: list[str]) -> list[Rule]:
    rules: list[Rule] = []
    for entry in raw:
        rid = entry.get("id")
        if not rid:
            errors.append(f"{kind} rule missing id: {entry}")
            continue
        match = entry.get("match") or {}
        for key in match:
            if key not in SUBJECT_FIELDS and key not in VIRTUAL_MATCHERS:
                errors.append(f"rule {rid}: unknown match field {key!r}")
        rule = Rule(
            id=rid,
            kind=kind,
            match=match,
            context=entry.get("context") or {},
            route=entry.get("route"),
            action=entry.get("action"),
            queue=entry.get("queue"),
            priority=int(entry.get("priority", 100)),
            provenance=entry.get("provenance") or {},
            review_by=entry.get("review_by"),
            note=entry.get("note", ""),
        )
        if kind == "screen":
            if rule.action not in SCREEN_ACTIONS:
                errors.append(f"screen rule {rid}: action must be one of {SCREEN_ACTIONS}")
            if rule.action == "park" and not rule.queue:
                errors.append(f"screen rule {rid}: park requires a queue")
        else:
            if not rule.route:
                errors.append(f"{kind} rule {rid}: missing route")
        if kind == "correction" and not rule.provenance:
            errors.append(f"correction {rid}: provenance is mandatory (date, decided_by, trigger)")
        rules.append(rule)
    return rules


def load_registry(registry_dir: str | Path, today: dt.date | None = None) -> Registry:
    """Load, validate, and return the registry.

    Structural problems raise RegistryError. Soft issues (stale review_by,
    duplicate rule ids across files) land in Registry.warnings so `validate`
    can surface them without blocking routing.
    """
    root = Path(registry_dir)
    errors: list[str] = []
    warnings: list[str] = []
    today = today or dt.date.today()

    channels = _parse_channels(_load_yaml_list(root / "channels.yaml"), errors)
    rules = (
        _parse_rules(_load_yaml_list(root / "screens.yaml"), "screen", errors)
        + _parse_rules(_load_yaml_list(root / "rules" / "identity.yaml"), "identity", errors)
        + _parse_rules(_load_yaml_list(root / "rules" / "corrections.yaml"), "correction", errors)
    )

    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            errors.append(f"duplicate rule id: {rule.id}")
        seen.add(rule.id)
        if rule.kind in ("identity", "correction") and rule.route not in channels:
            errors.append(f"rule {rule.id}: route {rule.route!r} is not a known channel")
        if rule.review_by:
            try:
                review = dt.date.fromisoformat(str(rule.review_by))
            except ValueError:
                errors.append(f"rule {rule.id}: review_by {rule.review_by!r} is not an ISO date")
            else:
                if review < today:
                    warnings.append(
                        f"rule {rule.id}: review_by {rule.review_by} has passed — "
                        "re-verify this fact (still active)"
                    )
        if rule.kind == "correction" and not rule.context:
            warnings.append(
                f"correction {rule.id}: no context predicate — consider whether this "
                "is really an identity rule"
            )

    if errors:
        raise RegistryError("registry invalid:\n  " + "\n  ".join(errors))
    if kinds := {r.kind for r in rules} - set(RULE_KINDS):
        raise RegistryError(f"internal: unexpected rule kinds {kinds}")
    return Registry(channels=channels, rules=rules, warnings=warnings)
