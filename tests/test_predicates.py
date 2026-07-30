"""Tests for dns_monitor.guards.predicates."""
from __future__ import annotations

import pytest

from dns_monitor.guards.predicates import (
    has_private_ip,
    has_public_ip,
    is_acme_challenge,
    is_address_record,
    is_blackhole,
    is_drift_protected,
    is_dyndns,
)
from dns_monitor.model.record import NormalizedRecord
from tests.conftest import make_record


@pytest.mark.parametrize("rtype,expected", [
    ("A", True),
    ("AAAA", True),
    ("MX", False),
    ("TXT", False),
    ("CNAME", False),
    ("NS", False),
])
def test_is_address_record(rtype, expected):
    assert is_address_record(make_record(type=rtype)) is expected


class TestIsDyndns:
    def test_short_ttl_a(self):
        assert is_dyndns(make_record(type="A", ttl=60))

    def test_at_threshold(self):
        assert is_dyndns(make_record(type="A", ttl=300))

    def test_above_threshold(self):
        assert not is_dyndns(make_record(type="A", ttl=301))

    def test_short_ttl_mx_not_dyndns(self):
        assert not is_dyndns(make_record(type="MX", ttl=60))

    def test_proxied_excluded(self):
        assert not is_dyndns(make_record(type="A", ttl=1, proxied=True))

    def test_custom_threshold(self):
        assert is_dyndns(make_record(type="A", ttl=600), ttl_threshold=600)
        assert not is_dyndns(make_record(type="A", ttl=601), ttl_threshold=600)


class TestHasPublicIp:
    def test_public_ipv4(self):
        assert has_public_ip(make_record(content="8.8.8.8"))

    def test_real_public(self):
        assert has_public_ip(make_record(content="77.181.39.185"))

    def test_rfc1918_10(self):
        assert not has_public_ip(make_record(content="10.0.0.1"))

    def test_rfc1918_192(self):
        assert not has_public_ip(make_record(content="192.168.1.1"))

    def test_rfc1918_172(self):
        assert not has_public_ip(make_record(content="172.16.0.1"))

    def test_loopback(self):
        assert not has_public_ip(make_record(content="127.0.0.1"))

    def test_non_ip_content(self):
        assert not has_public_ip(make_record(type="MX", content="mail.example.com"))

    def test_empty_content(self):
        assert not has_public_ip(make_record(content=""))


class TestHasPrivateIp:
    def test_rfc1918(self):
        assert has_private_ip(make_record(content="192.168.1.1"))

    def test_loopback(self):
        assert has_private_ip(make_record(content="127.0.0.1"))

    def test_public_not_private(self):
        assert not has_private_ip(make_record(content="8.8.8.8"))

    def test_non_ip(self):
        assert not has_private_ip(make_record(content="mail.example.com"))


def test_is_blackhole():
    assert is_blackhole(make_record(content="127.0.0.1"))
    assert is_blackhole(make_record(content="::1"))
    assert not is_blackhole(make_record(content="1.2.3.4"))


def test_is_acme_challenge():
    assert is_acme_challenge(make_record(name="_acme-challenge.example.com", type="TXT"))
    assert not is_acme_challenge(make_record(name="example.com", type="TXT"))
    assert not is_acme_challenge(make_record(name="acme.example.com", type="TXT"))


class TestIsDriftProtected:
    def test_static_a_protected(self):
        assert is_drift_protected(make_record(type="A", ttl=3600))

    def test_mx_protected(self):
        assert is_drift_protected(make_record(type="MX", ttl=3600))

    def test_dyndns_not_protected(self):
        assert not is_drift_protected(make_record(type="A", ttl=60))

    def test_acme_not_protected(self):
        assert not is_drift_protected(
            make_record(name="_acme-challenge.example.com", type="TXT", ttl=60)
        )
