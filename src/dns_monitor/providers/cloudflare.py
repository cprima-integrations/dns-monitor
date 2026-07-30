"""Cloudflare provider adapter."""
from __future__ import annotations

import logging

from ..model.record import NormalizedRecord

_log = logging.getLogger(__name__)


class CloudflareProvider:
    """Reads DNS zones and records from Cloudflare via the REST API.

    Requires a custom API token with Zone:Read + DNS:Read permissions only.
    No write permissions are needed or should be granted to the monitoring token.
    """

    def __init__(self, api_token: str) -> None:
        self._api_token = api_token
        self._cf = None

    @property
    def name(self) -> str:
        return "cloudflare"

    def __enter__(self) -> "CloudflareProvider":
        import cloudflare  # type: ignore[import]

        self._cf = cloudflare.Cloudflare(api_token=self._api_token)
        _log.debug("Cloudflare client initialised")
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self._cf = None

    def list_zones(self) -> list[str]:
        zones = sorted(z.name for z in self._cf.zones.list())  # type: ignore[union-attr]
        _log.debug("Cloudflare zones: %s", zones)
        return zones

    def get_records(self, zone: str) -> list[NormalizedRecord]:
        matched = list(self._cf.zones.list(name=zone))  # type: ignore[union-attr]
        if not matched:
            _log.warning("Cloudflare zone not found: %s", zone)
            return []
        zone_id = matched[0].id
        records = []
        for rec in self._cf.dns.records.list(zone_id=zone_id):  # type: ignore[union-attr]
            records.append(
                NormalizedRecord(
                    name=rec.name,
                    type=rec.type,
                    content=rec.content or "",
                    ttl=rec.ttl if rec.ttl and rec.ttl != 1 else 1,
                    provider="cloudflare",
                    zone=zone,
                    proxied=bool(rec.proxied),
                    raw=rec.model_dump(mode="json"),
                )
            )
        _log.debug("Cloudflare %s: %d records", zone, len(records))
        return records
