# dns-monitor

Multi-provider DNS zone guard that detects accidental edits and hijacking across INWX and Cloudflare zones.

**USP**: the package never calls mutating API methods — drift detection is the compensating control for providers that offer no read-only role.

## Installation

```bash
pip install dns-monitor          # library only
pip install dns-monitor[cli]     # + CLI and dotenv support
```

## Providers

| Provider | Auth | Minimum permissions |
|---|---|---|
| INWX | username + password | Domain Management, DNS Management (no read-only role exists) |
| Cloudflare | API token | Zone:Read + DNS:Read |

Set credentials in `.env` (see `.env.example`) or export them directly:

```bash
export INWX_USERNAME=svc-monitor-inwx
export INWX_PASSWORD=...
export CF_API_TOKEN=...
```

## CLI

```bash
dns-monitor zones              # list all zones across configured providers
dns-monitor baseline           # save current state as drift baseline
dns-monitor check              # check guards and detect drift
dns-monitor check --policies my_policies.py   # inject custom policies
```

Exit codes match violation severity: 0 = clean, 1 = MEDIUM, 2 = HIGH, 3 = CRITICAL.

## Library usage

```python
from dns_monitor.providers.inwx import InwxProvider
from dns_monitor.guards.policy import Policy
from dns_monitor.guards.predicates import is_address_record, has_public_ip
from dns_monitor.guards.runner import run_policies
from dns_monitor.model.severity import Severity

vpn_policy = Policy(
    name="vpn-endpoints-must-be-public",
    applies_to=lambda r: is_address_record(r) and r.name in VPN_HOSTNAMES,
    require=has_public_ip,
    severity=Severity.CRITICAL,
    message="{type} {name} → {content} is non-public — VPN tunnel at risk",
)

with InwxProvider(username, password) as p:
    for zone in p.list_zones():
        records = p.get_records(zone)
        violations = run_policies(records, [vpn_policy])
```

## Drift detection

```python
from dns_monitor.model import snapshot
from dns_monitor.guards.runner import run_drift

baseline = snapshot.load(Path("snapshots/latest.json"))
current = p.get_records(zone)
violations = run_drift(baseline.get(f"inwx:{zone}", []), current, zone=zone)
```

Records exempt from drift detection by default:
- A/AAAA with TTL ≤ 300 (DynDNS — expected to change with WAN IP)
- `_acme-challenge.*` TXT records (transient ACME DNS-01 challenge)

## Salt grains

Copy `src/dns_monitor/contrib/salt_grains.py` to `/srv/salt/_grains/`. The minion must have `dns_monitor[cli]` installed and `INWX_USERNAME`/`INWX_PASSWORD` in its environment.

Grain returned: `dns_monitor.inwx_zones` — list of zone names.

## License

MIT
