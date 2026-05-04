"""Phase 41 — Microsoft Endpoint / Defender / Tunnel / Edge for Business / Autopilot.

- Microsoft Tunnel: *.tunnel.microsoft.com
- Microsoft Edge for Business: edge-cloud.microsoft.com
- Windows Autopilot deployment URL pattern
- Microsoft Endpoint Manager / Intune admin deep-link
- Defender for Cloud (formerly Azure Security Center)
- Defender for Endpoint API surface
- Defender Vulnerability Management (TVM) API surface
- Compliance Manager
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, is_existence_signal


# (label, url_template, severity, why)
ENDPOINT_PROBES = [
    ("Microsoft Tunnel sensor pattern (per-tenant)",
     "https://{tenant}sensor.tunnel.microsoft.com",
     Severity.LOW,
     "Microsoft Tunnel uses tenant-specific subdomains for sensor enrollment. Existence indicates Tunnel deployment."),
    ("Microsoft Edge for Business cloud endpoint",
     "https://edge-cloud.microsoft.com",
     Severity.LOW,
     "Universal endpoint for Edge for Business cloud config."),
    ("Microsoft Endpoint Manager / Intune admin deep-link",
     "https://endpoint.microsoft.com/?tid={tid}",
     Severity.LOW,
     "Auth-gated deep-link to Endpoint Manager admin."),
    ("Microsoft Intune service URL",
     "https://manage.microsoft.com",
     Severity.LOW,
     "Universal."),
    ("Windows Autopilot enrollment endpoint",
     "https://enterpriseregistration.windows.net",
     Severity.LOW,
     "Universal Autopilot enrollment endpoint. Tenant-specific via JWT during real enrollment."),
    ("Defender for Cloud (formerly ASC) deep-link",
     "https://portal.azure.com/?tid={tid}#blade/Microsoft_Azure_Security/SecurityMenuBlade",
     Severity.LOW,
     "Auth-gated deep-link."),
    ("Defender for Endpoint API surface",
     "https://api.securitycenter.microsoft.com/api",
     Severity.LOW,
     "Universal MDE API base. Auth-gated; presence universal."),
    ("Defender Vulnerability Management TVM API",
     "https://api.security.microsoft.com",
     Severity.LOW,
     "Universal Defender API base."),
    ("Compliance Manager deep-link",
     "https://compliance.microsoft.com/?tid={tid}",
     Severity.LOW,
     "Auth-gated deep-link."),
]


async def probe(http: StealthClient, url: str) -> int | None:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    return r.status_code if r else None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand
    tid = snap.tenant_id or ""

    sem = asyncio.Semaphore(min(ctx.workers, 8))

    async def go(label: str, tpl: str, sev: Severity, why: str) -> None:
        url = (tpl.replace("{tenant}", tenant_short)
                  .replace("{brand}", brand)
                  .replace("{tid}", tid))
        async with sem:
            code = await probe(http, url)
        if code and is_existence_signal(code):
            findings.append(data(
                phase="microsoft_endpoint", check="microsoft_endpoint_surface",
                title=f"MS endpoint surface reachable: {label}",
                target=url, confidence=Confidence.MEDIUM,
                payload={"label": label, "url": url, "status": code, "why": why,
                         "severity_hint": sev.value if hasattr(sev, "value") else str(sev)},
            ))

    await asyncio.gather(*(go(lbl, tpl, sev, why) for lbl, tpl, sev, why in ENDPOINT_PROBES))

    return findings
