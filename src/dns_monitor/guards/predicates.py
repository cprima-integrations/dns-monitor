"""Pure predicate functions on NormalizedRecord.

All functions are injected into Policy.applies_to / Policy.require by the caller.
No personal constants (hostnames, domain names) are defined here.
"""
from __future__ import annotations

import ipaddress

from ..model.record import NormalizedRecord

DYNDNS_TTL_THRESHOLD = 300  # seconds; at or below = short-lived / DynDNS record


def is_address_record(rec: NormalizedRecord) -> bool:
    return rec.type in ("A", "AAAA")


def is_dyndns(rec: NormalizedRecord, ttl_threshold: int = DYNDNS_TTL_THRESHOLD) -> bool:
    """Short-TTL A/AAAA not behind a proxy — expected to track a changing WAN IP."""
    return is_address_record(rec) and rec.ttl <= ttl_threshold and not rec.proxied


def is_blackhole(rec: NormalizedRecord) -> bool:
    """Intentional DNS sink — content is loopback."""
    return rec.content.strip() in ("127.0.0.1", "::1")


def is_acme_challenge(rec: NormalizedRecord) -> bool:
    """Transient TXT record written during ACME DNS-01 challenge. Exempt from drift."""
    return rec.name.startswith("_acme-challenge.")


def is_drift_protected(rec: NormalizedRecord) -> bool:
    """Any record that must not change without explicit intent.

    DynDNS records and ACME challenge TXT records are excluded — they change
    by design and would generate false-positive drift alerts.
    """
    return not is_dyndns(rec) and not is_acme_challenge(rec)


def has_public_ip(rec: NormalizedRecord) -> bool:
    """Return True if content is a globally routable unicast IP address."""
    try:
        addr = ipaddress.ip_address(rec.content.strip())
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_unspecified
            or addr.is_link_local
            or addr.is_multicast
        )
    except ValueError:
        return False  # MX hostname, CNAME target, TXT value, etc.


def has_private_ip(rec: NormalizedRecord) -> bool:
    """Return True if content is an RFC1918 or loopback address."""
    try:
        addr = ipaddress.ip_address(rec.content.strip())
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False
