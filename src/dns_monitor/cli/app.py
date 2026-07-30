"""dns-monitor CLI — Typer + Rich frontend."""
from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="dns-monitor", no_args_is_help=True, add_completion=False)
console = Console()
err = Console(stderr=True)

_DEFAULT_SNAPSHOT = Path("snapshots/latest.json")

_SEV_COLOR = {
    "CRITICAL": "red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "INFO": "dim",
}


def _load_env() -> None:
    load_dotenv()


def _build_providers() -> list:
    providers = []
    username = os.getenv("INWX_USERNAME")
    password = os.getenv("INWX_PASSWORD")
    if username and password:
        from dns_monitor.providers.inwx import InwxProvider
        providers.append(InwxProvider(username, password))
    cf_token = os.getenv("CF_API_TOKEN")
    if cf_token:
        from dns_monitor.providers.cloudflare import CloudflareProvider
        providers.append(CloudflareProvider(cf_token))
    return providers


def _load_user_policies(path: str) -> tuple[list, list]:
    spec = importlib.util.spec_from_file_location("_user_policies", path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return getattr(mod, "policies", []), getattr(mod, "drift_policies", [])


@app.command()
def zones() -> None:
    """List all DNS zones across configured providers."""
    _load_env()
    providers = _build_providers()
    if not providers:
        err.print(
            "[red]No providers configured.[/red] "
            "Set INWX_USERNAME/INWX_PASSWORD or CF_API_TOKEN."
        )
        raise typer.Exit(1)
    table = Table("Provider", "Zone", title="DNS Zones")
    for p in providers:
        with p:
            for z in p.list_zones():
                table.add_row(p.name, z)
    console.print(table)


@app.command()
def baseline(
    snapshot: Path = typer.Option(_DEFAULT_SNAPSHOT, help="Snapshot output path"),
) -> None:
    """Save current DNS state as baseline for drift detection."""
    _load_env()
    from dns_monitor.model import snapshot as snap_io

    providers = _build_providers()
    if not providers:
        err.print("[red]No providers configured.[/red]")
        raise typer.Exit(1)
    zones_data: dict = {}
    for p in providers:
        with p:
            for z in p.list_zones():
                key = f"{p.name}:{z}"
                zones_data[key] = p.get_records(z)
    snap_io.save(zones_data, snapshot)
    total = sum(len(v) for v in zones_data.values())
    console.print(
        f"[green]Baseline saved[/green] → {snapshot} "
        f"({total} records across {len(zones_data)} zones)"
    )


@app.command()
def check(
    snapshot: Path = typer.Option(_DEFAULT_SNAPSHOT, help="Baseline snapshot path"),
    policies_file: str = typer.Option(
        None, "--policies", help="Python file exporting policies / drift_policies lists"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show INFO violations too"),
) -> None:
    """Check current DNS state against guards and baseline drift."""
    _load_env()
    from dns_monitor.guards.runner import run_drift, run_policies
    from dns_monitor.model import snapshot as snap_io

    point_policies: list = []
    drift_policies: list = []
    if policies_file:
        point_policies, drift_policies = _load_user_policies(policies_file)

    providers = _build_providers()
    if not providers:
        err.print("[red]No providers configured.[/red]")
        raise typer.Exit(1)

    base_data = snap_io.load(snapshot)
    current_zones: dict = {}
    all_violations = []

    for p in providers:
        with p:
            for z in p.list_zones():
                key = f"{p.name}:{z}"
                records = p.get_records(z)
                current_zones[key] = records
                all_violations.extend(run_policies(records, point_policies))

    if base_data is None:
        console.print(
            "[yellow]No baseline found — run 'dns-monitor baseline' first to enable drift detection.[/yellow]"
        )
    else:
        for key, records in current_zones.items():
            zone_label = key.split(":", 1)[1] if ":" in key else key
            all_violations.extend(
                run_drift(base_data.get(key, []), records, zone=zone_label, policies=drift_policies)
            )

    visible = [v for v in all_violations if verbose or v.severity.value > 0]

    if not visible:
        console.print("[green]All guards passed. No violations.[/green]")
        raise typer.Exit(0)

    table = Table("Severity", "Record", "Message", title="Violations")
    for v in sorted(visible, key=lambda x: x.severity, reverse=True):
        rec_label = f"{v.record.type} {v.record.name}" if v.record else ""
        color = _SEV_COLOR.get(v.severity.name, "white")
        table.add_row(f"[{color}]{v.severity.name}[/{color}]", rec_label, v.message)
    console.print(table)

    max_sev = max(v.severity for v in all_violations)
    raise typer.Exit(int(max_sev))


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    app()
