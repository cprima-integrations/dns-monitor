"""Cedar-inspired declarative policy types.

Callers (homelab scripts, Salt modules) import these and instantiate their own
policies — no personal constants live in this module.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..model.record import NormalizedRecord
from ..model.severity import Severity


@dataclass
class Policy:
    """Point-in-time guard: applies_to selects records, require is the invariant."""

    name: str
    applies_to: Callable[[NormalizedRecord], bool]
    require: Callable[[NormalizedRecord], bool]
    severity: Severity
    message: str  # may use {name} {type} {content} {ttl} {provider} {zone}


@dataclass
class DriftPolicy:
    """Drift guard: modifies default HIGH severity for matching new/deleted records.

    Set allow_if to downgrade a drift event to INFO (e.g. new wind-name record).
    """

    name: str
    applies_to: Callable[[NormalizedRecord], bool]
    severity: Severity = Severity.HIGH
    allow_if: Callable[[NormalizedRecord], bool] = field(default=lambda _: False)
