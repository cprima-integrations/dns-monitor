"""INWX DomRobot provider adapter."""
from __future__ import annotations

import logging

from ..model.record import NormalizedRecord

_log = logging.getLogger(__name__)

_API_URL = "https://api.domrobot.com"


class InwxProvider:
    """Reads DNS zones and records from INWX via the DomRobot XML-RPC API.

    The monitoring account technically holds Domain Management + DNS Management
    roles (no read-only role exists at INWX). This adapter only calls read
    methods and must never call any mutating API method.
    """

    def __init__(self, username: str, password: str, api_url: str = _API_URL) -> None:
        self._username = username
        self._password = password
        self._api_url = api_url
        self._client = None

    @property
    def name(self) -> str:
        return "inwx"

    def __enter__(self) -> "InwxProvider":
        from INWX.Domrobot import ApiClient, ApiType  # type: ignore[import]

        self._client = ApiClient(api_url=self._api_url, api_type=ApiType.XML_RPC)
        r = self._client.call_api(
            "account.login",
            {"lang": "en", "user": self._username, "pass": self._password},
        )
        if r.get("code") != 1000:
            raise RuntimeError(
                f"INWX login failed [{r.get('code')}]: {r.get('msg')} — "
                "check that domrobot/API access is enabled for this sub-user in INWX portal"
            )
        _log.debug("INWX session opened for %s", self._username)
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if self._client is not None:
            self._client.call_api("account.logout", {})
            _log.debug("INWX session closed")
            self._client = None

    def list_zones(self) -> list[str]:
        r = self._client.call_api("nameserver.list", {})  # type: ignore[union-attr]
        domains = sorted(d["domain"] for d in r.get("resData", {}).get("domains", []))
        _log.debug("INWX zones: %s", domains)
        return domains

    def get_records(self, zone: str) -> list[NormalizedRecord]:
        r = self._client.call_api("nameserver.info", {"domain": zone})  # type: ignore[union-attr]
        raw_records = r.get("resData", {}).get("record", [])
        records = [
            NormalizedRecord(
                name=rec["name"],
                type=rec["type"],
                content=rec.get("content", ""),
                ttl=rec.get("ttl", 3600),
                provider="inwx",
                zone=zone,
                proxied=False,
                raw=dict(rec),
            )
            for rec in raw_records
        ]
        _log.debug("INWX %s: %d records", zone, len(records))
        return records
