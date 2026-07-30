"""Policy runners — evaluate records against Policy and DriftPolicy lists."""
from __future__ import annotations

from ..model.record import NormalizedRecord
from ..model.severity import Severity
from ..model.violation import Violation
from .policy import DriftPolicy, Policy
from .predicates import is_drift_protected


def run_policies(
    records: list[NormalizedRecord],
    policies: list[Policy],
) -> list[Violation]:
    """Evaluate point-in-time policies against a record set."""
    violations: list[Violation] = []
    for rec in records:
        for policy in policies:
            if policy.applies_to(rec) and not policy.require(rec):
                msg = policy.message.format(
                    name=rec.name,
                    type=rec.type,
                    content=rec.content,
                    ttl=rec.ttl,
                    provider=rec.provider,
                    zone=rec.zone,
                )
                violations.append(Violation(severity=policy.severity, message=msg, record=rec))
    return violations


def _record_key(rec: NormalizedRecord) -> tuple[str, str, str]:
    return (rec.name.rstrip("."), rec.type, rec.content.strip())


def _record_label(rec: NormalizedRecord) -> str:
    return f"{rec.type} {rec.name} → {rec.content!r} TTL={rec.ttl}"


def run_drift(
    baseline: list[NormalizedRecord],
    current: list[NormalizedRecord],
    zone: str = "",
    policies: list[DriftPolicy] | None = None,
) -> list[Violation]:
    """Detect additions, deletions, and TTL mutations in drift-protected records.

    DriftPolicy list lets callers downgrade specific drift events (e.g. a new
    wind-name record) to INFO instead of HIGH without changing the framework.
    """
    violations: list[Violation] = []
    prefix = f"[{zone}] " if zone else ""
    drift_policies: list[DriftPolicy] = policies or []

    base = {_record_key(r): r for r in baseline if is_drift_protected(r)}
    curr = {_record_key(r): r for r in current if is_drift_protected(r)}

    def _severity(rec: NormalizedRecord, default: Severity) -> Severity:
        for dp in drift_policies:
            if dp.applies_to(rec):
                return Severity.INFO if dp.allow_if(rec) else dp.severity
        return default

    for key in set(curr) - set(base):
        rec = curr[key]
        violations.append(Violation(
            _severity(rec, Severity.HIGH),
            f"{prefix}New record appeared: {_record_label(rec)}",
            rec,
        ))

    for key in set(base) - set(curr):
        rec = base[key]
        violations.append(Violation(
            _severity(rec, Severity.HIGH),
            f"{prefix}Record deleted: {_record_label(rec)}",
            rec,
        ))

    for key in set(base) & set(curr):
        b_ttl = base[key].ttl
        c_ttl = curr[key].ttl
        if b_ttl != c_ttl:
            rec = curr[key]
            violations.append(Violation(
                Severity.MEDIUM,
                f"{prefix}TTL changed {b_ttl} → {c_ttl}: {_record_label(rec)}",
                rec,
            ))

    return violations
