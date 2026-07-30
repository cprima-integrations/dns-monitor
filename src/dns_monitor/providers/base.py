"""Provider protocol — implemented by every DNS backend adapter."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..model.record import NormalizedRecord


@runtime_checkable
class Provider(Protocol):
    @property
    def name(self) -> str: ...

    def list_zones(self) -> list[str]: ...

    def get_records(self, zone: str) -> list[NormalizedRecord]: ...

    def __enter__(self) -> Provider: ...

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None: ...
