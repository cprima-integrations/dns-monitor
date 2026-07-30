"""Snapshot persistence — save/load zone records to/from JSON."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .record import NormalizedRecord


def save(zones: dict[str, list[NormalizedRecord]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {zone: [asdict(r) for r in records] for zone, records in zones.items()}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load(path: Path) -> dict[str, list[NormalizedRecord]] | None:
    if not path.exists():
        return None
    with open(path) as f:
        data = json.load(f)
    return {
        zone: [NormalizedRecord(**r) for r in records]
        for zone, records in data.items()
    }
