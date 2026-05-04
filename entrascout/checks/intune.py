"""Phase 22 — Microsoft Intune / MDM detection (gap #12).

Probes:
- enterpriseregistration.{domain} — DRS endpoint already covered in dns_surface
- enterpriseenrollment.{domain} — Intune enrollment DNS
- {tenant_id}.manage.microsoft.com — Intune service URL
- AutoDiscover MDM URL

This complements identity_edges. Read-only DNS + HEAD probes.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, is_existence_signal


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()

    sem = asyncio.Semaphore(min(ctx.workers, 6))

    async def probe(url: str, check: str, title: str, sev: Severity = Severity.LOW) -> None:
        async with sem:
            r = await http.head(url)
            if not r:
                r = await http.get(url)
        if r and is_existence_signal(r.status_code):
            findings.append(data(
                phase="intune", check=check, title=f"{title}: {url}",
                target=url, confidence=Confidence.HIGH,
                payload={"url": url, "status": r.status_code},
                tags=[ChainTag.SVC_INTUNE_DETECTED],
            ))

    # Intune enrollment DNS (may be a CNAME — DNS resolution itself is the signal)
    probes = [
        (f"https://enterpriseenrollment.{apex}", "intune_enrollment_dns",
         "Intune enrollment endpoint detected"),
        ("https://manage.microsoft.com",
         "intune_service_reachable", "Intune Service Hub reachable (universal)"),
    ]
    if snap.tenant_id:
        probes.append((
            f"https://{snap.tenant_id}.manage.microsoft.com",
            "intune_tenant_manage_url",
            "Intune tenant-scoped service URL",
        ))

    await asyncio.gather(*(probe(u, c, t) for u, c, t in probes))

    return findings
