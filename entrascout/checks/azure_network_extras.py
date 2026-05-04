"""Phase 40 — Azure networking extras (SignalR, Web PubSub, Bastion, Relay,
Notification Hubs, Private Link DNS leak)."""
from __future__ import annotations

import asyncio

from ..dns_client import query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


def variants(brand: str) -> list[str]:
    if not brand or len(brand) < 3:
        return []
    return list(dict.fromkeys([
        brand, f"{brand}-prod", f"{brand}signalr", f"{brand}-signalr",
        f"{brand}-pubsub", f"{brand}-relay", f"{brand}-bastion", f"{brand}-nh",
    ]))


async def probe_url(http: StealthClient, url: str, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        r = await http.head(url)
    if not r:
        async with sem:
            r = await http.get(url)
    return r.status_code if r else None


async def safe_query(name: str, rtype: str) -> list[str]:
    try:
        return await query(name, rtype, timeout=4.0)
    except Exception:
        return []


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    if "-" in brand:
        brand = brand.split("-")[0]
    if not brand or len(brand) < 3:
        return findings

    sem = asyncio.Semaphore(min(ctx.workers, 12))

    # ---- SignalR Service: {name}.service.signalr.net ----
    async def signalr(name: str) -> None:
        url = f"https://{name}.service.signalr.net"
        code = await probe_url(http, url, sem)
        if code in (200, 401, 403, 404):
            if code != 404:
                findings.append(lead(
                    phase="azure_network_extras", check="signalr_endpoint",
                    title=f"Azure SignalR Service: {url}",
                    target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                    data={"url": url, "name": name, "status": code},
                ))

    # ---- Web PubSub: {name}.webpubsub.azure.com ----
    async def webpubsub(name: str) -> None:
        url = f"https://{name}.webpubsub.azure.com"
        code = await probe_url(http, url, sem)
        if code in (200, 401, 403):
            findings.append(lead(
                phase="azure_network_extras", check="webpubsub_endpoint",
                title=f"Azure Web PubSub: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                data={"url": url, "name": name, "status": code},
            ))

    # ---- Bastion: {name}.bastion.azure.com ----
    async def bastion(name: str) -> None:
        url = f"https://{name}.bastion.azure.com"
        code = await probe_url(http, url, sem)
        if code in (200, 301, 302, 401, 403):
            findings.append(lead(
                phase="azure_network_extras", check="bastion_endpoint",
                title=f"Azure Bastion: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                description="Azure Bastion endpoint detected — used for browser-based RDP/SSH.",
                data={"url": url, "name": name, "status": code},
            ))

    for n in variants(brand)[:3]:
        await asyncio.gather(signalr(n), webpubsub(n), bastion(n))

    # ---- Private Link DNS leak — sometimes private FQDNs appear in public DNS ----
    # Pattern: {something}.privatelink.{service}.windows.net or .azure.com
    privatelink_targets = [
        f"privatelink.blob.core.windows.net",
        f"privatelink.vault.azure.net",
        f"privatelink.azurewebsites.net",
        f"privatelink.database.windows.net",
        f"privatelink.servicebus.windows.net",
    ]
    # We only get useful signal if the ORG's public DNS has CNAMEs to privatelink.* targets.
    # Filter to hosts under the org apex — universal MS hosts (app.powerbi.com etc.) CNAME
    # to privatelink as part of normal MS infra and aren't a leak from THIS tenant.
    cnames_seen: list[str] = []
    seen_hosts: set[str] = set()
    for f in om.findings:
        host = (f.target or "").replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if not host or "." not in host or host in seen_hosts:
            continue
        # Only check hosts under the org apex
        if not (host == apex or host.endswith("." + apex)):
            continue
        seen_hosts.add(host)
        cnames = await safe_query(host, "CNAME")
        for c in cnames:
            if "privatelink." in c.lower():
                cnames_seen.append({"host": host, "cname": c})  # type: ignore

    if cnames_seen:
        findings.append(lead(
            phase="azure_network_extras", check="privatelink_dns_leak",
            title=f"Azure Private Link DNS leak — {len(cnames_seen)} public hosts CNAME to privatelink.*",
            target=apex, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            description=(
                "One or more public DNS records resolve to `privatelink.*` Azure namespaces. "
                "These records are typically supposed to live in private DNS zones; their "
                "presence in public DNS leaks the resource type and name to any internet "
                "observer."
            ),
            data={"private_link_cnames": cnames_seen},
            recommendation="Move these records to an Azure Private DNS Zone; remove from public DNS.",
        ))

    return findings
