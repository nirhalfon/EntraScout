"""EntraScout CLI."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .logging import configure as configure_logging
from .runner import run_engagement

console = Console()


def _print_banner() -> None:
    console.print(Panel.fit(
        "[bold cyan]EntraScout[/bold cyan]  ·  [dim]External + Internal M365 / Entra ID / Azure recon[/dim]\n"
        "[dim]Authorized testing only. Built for red team & pentest engagements.[/dim]",
        border_style="cyan",
    ))


def _phase_descriptions() -> dict[str, str]:
    """Short one-liner per phase, used for --list-phases."""
    return {
        "tenant": "Tenant fingerprint (ID, region, cloud, branding)",
        "federation": "Federation type + ADFS deep (MEX, RP catalog, ClaimsXray)",
        "user_enum": "User enumeration (GetCredentialType, OneDrive timing, Teams)",
        "m365_services": "M365 service surface (SP, OneDrive, Exchange, Teams, Yammer, Lync)",
        "dns_surface": "DNS / mail surface (MX, SPF, DMARC, DKIM, autodiscover)",
        "auth_surface": "Auth attack surface (legacy banners, ROPC, AADSTS, lockout, device-code)",
        "oauth": "Token / OAuth (FOCI client probing, device-code surface)",
        "defense_posture": "Defense roll-up (mail spoofing, legacy auth, ADFS exposure)",
        "tenant_linkage": "Sibling domains in same tenant (M&A leakage)",
        "bing_dorks": "Microsoft-specific Bing dork pack",
        "copilot": "M365 Copilot + Copilot Studio detection",
        "power_platform": "Power Pages + OData leak, Dynamics 365 multi-region + sovereign",
        "azure_resources": "Azure resources (App Service, Kudu, Storage, ACR, SWA, FD, CDN, etc.)",
        "identity_edges": "AAD App Proxy, Defender for Cloud Apps tenant, DRS endpoints",
        "ms_public_content": "Bookings, Forms, Stream, Loop, Power BI public, Yammer external",
        "azure_subdomain_enum": "Key Vault, OpenAI, Cognitive, App Service deployment slots",
        "aad_apps": "App Registration enum, B2C tenant, Graph metadata",
        "github_dorks": "GitHub code-search dork pack (auto-execute with GITHUB_TOKEN)",
        "logic_apps": "Logic App / Power Automate trigger URL hunt-pack",
        "ado_deep": "Azure DevOps deeper (legacy visualstudio.com, marketplace, pipelines)",
        "onedrive_links": "OneDrive / SharePoint anonymous-link search dorks",
        "intune": "Intune / MDM endpoints",
        "guest_inference": "Cross-tenant B2B / guest signaling baseline",
        "wayback": "Archive.org CDX historical sweep",
        "tenant_directory": "Reverse map: sibling domains in different tenants",
        "defender_posture": "Defender / MCAS / Sentinel / SOAR webhook / MIP roll-up",
        "package_leaks": "NPM scope, PyPI prefix, Docker Hub namespace",
        "cert_san": "crt.sh CT-log SAN sweep for related hostnames",
        "sharepoint_recon": "SharePoint deep (site enum, REST API, anonymous search-API test)",
        "azure_data_services": "Cosmos / SQL / Redis / Data Lake / Event Grid / IoT / SB / Container Apps",
        "mfa_gaps": "MFA bypass surfaces (EXO basic auth, ADFS WS-Trust, ROPC)",
        "functions_unauth": "Azure Function App `/api/{name}` brute force",
        "dark_corners": "Niche MS surfaces (Sway, Visio, Project, Bookings With Me, etc.)",
        "authenticated": "Authenticated Graph mode (--token required)",
        "dns_intel": "Deep DNS intel (TXT mining, DKIM brute, SRV, CAA, DNSSEC, MTA-STS)",
        "subdomain_takeover": "Microsoft-specific subdomain takeover hunter",
        "http_headers": "HSTS / CSP / XFO / COOP / COEP roll-up + info-leak detection",
        "azure_compute_extras": "AKS public API, Service Fabric, Batch, Spring Apps, Lab Services",
        "azure_data_extras": "Synapse, Data Factory, Databricks, HDInsight, AML, Health Bot, FHIR",
        "azure_network_extras": "SignalR, Web PubSub, Bastion, Private Link DNS leak",
        "microsoft_endpoint": "Tunnel, Edge for Business, Endpoint Manager, Defender APIs, TVM",
        "dynamics_deep": "D365 CRM Web API direct, Power Pages vanity domains, AppSource",
        "entra_advanced": "External ID + OIDC, Verified ID, Workload, Governance, ZTNA, PIM",
        "teams_deep": "Teams Live Events / Webinars + incoming-webhook hunt + Phone System",
        "office_extras": "OneNote, Office Online, Lists consumer, Clipchamp, Editor",
        "cross_saas": "15 cross-SaaS tenant existence probes (Atlassian/Slack/Zoom/etc.)",
        "breach_intel": "HIBP + paste-site dork pack",
        "webhook_hunt": "Teams + Outlook + Logic Apps + Functions + Slack/Discord webhook leak hunt",
        "subscription_leak": "Azure subscription ID leak hunt-pack + GUID extraction",
        "power_pages_odata_deep": "Specific Dataverse entity-set anonymous-read probes",
        "final_gaps": "Service Fabric, ACI, VPN/ER, Relay, NH, Stream Analytics, IRM, PVA",
        "internal_mode": "Internal-mode probes (assume corp-net foothold) — use with --internal",
    }


def _print_phases() -> None:
    """Print all phases in a numbered table."""
    from .checks import PHASES
    descs = _phase_descriptions()
    table = Table(title="📋 EntraScout Phases", border_style="cyan", show_lines=False)
    table.add_column("#", style="bold cyan", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("Description", style="dim")
    # Sort numerically; "internal" goes last
    keys = list(PHASES.keys())
    keys.sort(key=lambda k: (1, k) if not k.isdigit() else (0, int(k)))
    for k in keys:
        name, _ = PHASES[k]
        desc = descs.get(name, "")
        display_k = k if k.isdigit() else "—"
        table.add_row(display_k, name, desc)
    console.print(table)
    console.print("\n[dim]Use --phases with numbers or names, e.g.[/dim]")
    console.print("  [cyan]entrascout target.com --phases 1,2,29[/cyan]")
    console.print("  [cyan]entrascout target.com --phases tenant,federation,sharepoint_recon[/cyan]")
    console.print("  [cyan]entrascout target.com --internal[/cyan]    # auto-includes internal_mode\n")


def _resolve_phases(phases_str: str) -> list[str]:
    """Accept comma-separated numbers OR names; return canonical phase keys.

    Numbers map directly. Names are reverse-mapped via PHASES.
    Unknown tokens raise ClickException with a hint.
    """
    from .checks import PHASES
    name_to_key = {name: key for key, (name, _) in PHASES.items()}
    out: list[str] = []
    bad: list[str] = []
    for tok in (t.strip() for t in phases_str.split(",")):
        if not tok:
            continue
        if tok in PHASES:
            out.append(tok)
        elif tok in name_to_key:
            out.append(name_to_key[tok])
        else:
            bad.append(tok)
    if bad:
        raise click.ClickException(
            f"Unknown phase(s): {', '.join(bad)}. Run 'entrascout --list-phases' to see all phases."
        )
    return out


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.argument("target", required=False)
@click.option("--internal", "mode_internal", is_flag=True,
              help="Also run internal-mode probes (assume the host is on the corporate network).")
@click.option("--user", "user_hint", default=None,
              help="A known user@domain to seed user-enum (e.g. ceo@target.com).")
@click.option("--token", "token", default=None,
              help="Optional auth token (Graph PAT etc) — never written to disk.")
@click.option("--bing-key", "bing_api_key", default=None,
              help="Bing Web Search API subscription key for automated dorks.")
@click.option("--output", "output_root", default="./output", show_default=True,
              help="Where to write the per-run output folder.")
@click.option("--quick", is_flag=True, help="Faster scan with reduced coverage.")
@click.option("--stealth", is_flag=True, help="Stealth mode: low QPS + jitter + randomized order.")
@click.option("--phases", default=None,
              help="Comma-separated phase numbers OR names. Use --list-phases to see them. "
                   "Examples: '1,2,29' or 'tenant,federation,sharepoint_recon'. Default: all.")
@click.option("--list-phases", is_flag=True, help="Print all phases (numbers, names, descriptions) and exit.")
@click.option("--timeout", default=8.0, show_default=True, type=float, help="Per-request timeout (s).")
@click.option("--workers", default=32, show_default=True, type=int, help="Concurrent workers.")
@click.option("--proxy", default=None, help="Proxy URL (e.g. socks5://127.0.0.1:9050).")
@click.option("--log-level", default="DEBUG", show_default=True,
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              help="Console + file log level.")
@click.option("--no-banner", is_flag=True, help="Suppress the banner.")
def main(
    target: str,
    mode_internal: bool,
    user_hint: str | None,
    token: str | None,
    bing_api_key: str | None,
    output_root: str,
    quick: bool,
    stealth: bool,
    phases: str | None,
    list_phases: bool,
    timeout: float,
    workers: int,
    proxy: str | None,
    log_level: str,
    no_banner: bool,
) -> None:
    """Run EntraScout against TARGET (a domain like example.com).

    Examples:

        entrascout target.com
        entrascout target.com --internal --user ceo@target.com
        entrascout target.com --phases 1,2,29              # by number
        entrascout target.com --phases tenant,federation   # by name
        entrascout --list-phases                            # show all phases
    """
    # Handle --list-phases early — no target needed
    if list_phases:
        _print_phases()
        sys.exit(0)

    if not target:
        raise click.UsageError("TARGET is required (e.g. 'entrascout example.com'). Use --list-phases to see available phases.")

    if not no_banner:
        _print_banner()

    # Pull from env if not specified
    bing_api_key = bing_api_key or os.environ.get("BING_API_KEY")
    token = token or os.environ.get("ENTRASCOUT_TOKEN")

    selected_phases: list[str] | None = None
    if phases:
        selected_phases = _resolve_phases(phases)

    output_dir = Path(output_root)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Stage logs into a temp run dir-like name; the runner will create its own run dir,
    # so we configure logging once we know it.
    # Strategy: create the run dir first, then configure logging into it.
    # Easier: configure logging into output_dir, then move the log.
    # Simpler still: place a session-level log under output_dir/_session.log
    # and per-run logs are inside each run via the runner.
    # For now we place logs at output_dir/last_run.log.
    log_dir = output_dir
    logger, history = configure_logging(log_dir=log_dir, level=log_level)

    logger.info("EntraScout starting (target=%s, internal=%s)", target, mode_internal)

    try:
        result = asyncio.run(run_engagement(
            target=target,
            output_root=output_root,
            mode_internal=mode_internal,
            user_hint=user_hint,
            token=token,
            bing_api_key=bing_api_key,
            quick=quick,
            stealth=stealth,
            selected_phases=selected_phases,
            timeout=timeout,
            workers=workers,
            proxy=proxy,
            history_writer=history,
        ))
    finally:
        history.close()

    # Pretty summary
    counts = result["counts"]
    table = Table(title="📊 Run summary", border_style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ("critical", "high", "medium", "low", "info"):
        table.add_row(sev.upper(), str(counts.get(sev, 0)))
    table.add_row("[bold]Leads[/bold]", str(counts.get("leads", 0)))
    table.add_row("[bold]Issues[/bold]", str(counts.get("issues", 0)))
    table.add_row("[bold]Validations[/bold]", str(counts.get("validations", 0)))
    table.add_row("[bold]Total findings[/bold]", str(counts.get("total", 0)))
    console.print(table)

    chain_summary = result.get("chain_summary", {})
    if chain_summary.get("total_paths"):
        console.print(f"\n🎯 [bold red]{chain_summary['total_paths']}[/bold red] attack path(s) triggered. "
                      f"See [cyan]{result['run_dir']}/attack_paths.md[/cyan].")

    console.print(f"\n📁 Output: [bold]{result['run_dir']}[/bold]")
    console.print(f"   ├─ [cyan]report.html[/cyan]   (open in browser)")
    console.print(f"   ├─ [cyan]findings.json[/cyan] (all findings)")
    console.print(f"   ├─ [cyan]issues.json[/cyan]   (security issues)")
    console.print(f"   ├─ [cyan]leads.json[/cyan]    (next-step opportunities)")
    console.print(f"   ├─ [cyan]chain.json[/cyan]    (attack-chain graph)")
    console.print(f"   ├─ [cyan]attack_paths.md[/cyan] (top paths in plain English)")
    console.print(f"   ├─ [cyan]recommendations.md[/cyan]")
    console.print(f"   ├─ [cyan]history.jsonl[/cyan] (every HTTP probe)")
    console.print(f"   └─ [cyan]raw/[/cyan]          (preserved evidence)")


if __name__ == "__main__":
    main()
