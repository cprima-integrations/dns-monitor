from __future__ import annotations

from dataclasses import dataclass

from .severity import Severity
from .record import NormalizedRecord


@dataclass
class Violation:
    severity: Severity
    message:  str
    record:   NormalizedRecord | None = None

    def __str__(self) -> str:
        rec = self.record
        loc = f" [{rec.type} {rec.name} @ {rec.provider}]" if rec else ""
        return f"[{self.severity.name}]{loc} {self.message}"
