"""NormalizedRecord — shared currency across all DNS providers."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NormalizedRecord:
    name:     str        # FQDN
    type:     str        # A, AAAA, MX, TXT, CNAME, NS, SRV, …
    content:  str        # IP / hostname / TXT value
    ttl:      int
    provider: str        # "inwx" | "cloudflare" | …
    zone:     str        # zone/domain this record belongs to
    proxied:  bool = False        # Cloudflare proxy flag
    raw:      dict = field(default_factory=dict)
