"""Shared fixtures for dns_monitor tests."""
from __future__ import annotations

import pytest

from dns_monitor.model.record import NormalizedRecord


def make_record(
    name: str = "test.example.com",
    type: str = "A",
    content: str = "1.2.3.4",
    ttl: int = 3600,
    provider: str = "inwx",
    zone: str = "example.com",
    proxied: bool = False,
    **kwargs,
) -> NormalizedRecord:
    return NormalizedRecord(
        name=name,
        type=type,
        content=content,
        ttl=ttl,
        provider=provider,
        zone=zone,
        proxied=proxied,
        raw=kwargs.pop("raw", {}),
    )


@pytest.fixture
def static_a() -> NormalizedRecord:
    return make_record(type="A", content="203.0.113.1", ttl=3600)


@pytest.fixture
def dyndns_a() -> NormalizedRecord:
    return make_record(type="A", content="203.0.113.2", ttl=60)


@pytest.fixture
def mx_record() -> NormalizedRecord:
    return make_record(type="MX", content="mail.example.com", ttl=3600)


@pytest.fixture
def acme_txt() -> NormalizedRecord:
    return make_record(
        name="_acme-challenge.example.com",
        type="TXT",
        content="sometoken",
        ttl=60,
    )


@pytest.fixture
def blackhole_a() -> NormalizedRecord:
    return make_record(type="A", content="127.0.0.1", ttl=3600)
