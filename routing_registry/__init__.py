"""Learning routing registry — deterministic fix-channel routing that accretes
rules from observed misroutes. See routing-registry/README.md."""

from .corrections import propose_correction
from .loader import RegistryError, load_registry
from .models import Channel, Registry, RouteResult, Rule
from .router import route_all, route_finding, stats

__all__ = [
    "Channel",
    "Registry",
    "RegistryError",
    "RouteResult",
    "Rule",
    "load_registry",
    "propose_correction",
    "route_all",
    "route_finding",
    "stats",
]
