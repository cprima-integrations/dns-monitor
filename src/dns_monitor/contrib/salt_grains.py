"""Salt external grains module for dns_monitor.

Drop this file into /srv/salt/_grains/ (or the configured grains dir) on the
Salt master. The minion must have dns_monitor installed in its Python environment.

Grains returned:
  dns_monitor:
    inwx_zones: [list of zone names]
    zone_count: N
    error: "..." (only on failure)
"""
from __future__ import annotations

__virtualname__ = "dns_monitor"


def __virtual__() -> bool | tuple[bool, str]:
    try:
        import dns_monitor  # noqa: F401
        return __virtualname__
    except ImportError:
        return False, "dns_monitor package not installed"


def grains() -> dict:
    try:
        import os

        from dns_monitor.providers.inwx import InwxProvider

        username = os.getenv("INWX_USERNAME")
        password = os.getenv("INWX_PASSWORD")
        if not (username and password):
            return {"dns_monitor": {"error": "INWX_USERNAME / INWX_PASSWORD not set"}}

        with InwxProvider(username, password) as p:
            zone_list = p.list_zones()

        return {"dns_monitor": {"inwx_zones": zone_list, "zone_count": len(zone_list)}}
    except Exception as exc:  # noqa: BLE001
        return {"dns_monitor": {"error": str(exc)}}
