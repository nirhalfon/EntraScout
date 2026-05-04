"""Phase 25 — Tenant directory reverse map (gap #19).

`https://login.microsoftonline.com/{ANYTHING}/v2.0/.well-known/openid-configuration`
returns the tenant ID for any verified domain that lives in some Entra tenant.

We use this both forward (target.com → tenant_id, already in tenant.py) and
REVERSE — given a tenant ID we already have, probe related verified domains
that appear in MX/SPF/AutoDiscover records to confirm they're sibling tenants.

Some orgs have multiple Entra tenants (M&A, regional split). Discovering
sibling tenants is a privacy/recon win.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()

    # Pull candidate sibling domains from prior `tenant_linkage` findings.
    candidates: list[str] = []
    for f in om.findings:
        if "sibling" in (f.check or "").lower() or "linked_domain" in (f.check or "").lower():
            d = (f.data or {}).get("domain") or (f.data or {}).get("sibling")
            if isinstance(d, str) and d:
                candidates.append(d.lower())
    candidates = list(dict.fromkeys(candidates))
    if not candidates:
        return findings

    sem = asyncio.Semaphore(min(ctx.workers, 6))
    seen_tenants: dict[str, str] = {}  # tenant_id → first domain seen
    if snap.tenant_id:
        seen_tenants[snap.tenant_id] = apex

    async def reverse_lookup(domain: str) -> None:
        url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
        async with sem:
            r = await http.get(url)
        if not r or r.status_code != 200:
            return
        try:
            j = r.json()
            issuer = j.get("issuer", "")
            tid = issuer.split("/")[3] if "sts.windows.net/" in issuer else issuer.rstrip("/").split("/")[-2]
            if tid and tid not in seen_tenants:
                seen_tenants[tid] = domain
                findings.append(lead(
                    phase="tenant_directory", check="sibling_tenant_distinct",
                    title=f"Sibling domain `{domain}` belongs to a DIFFERENT tenant ({tid})",
                    target=domain, severity=Severity.LOW, confidence=Confidence.HIGH,
                    description=(
                        f"Domain {domain} resolves to tenant {tid}, distinct from the primary tenant "
                        f"({snap.tenant_id}). This is normal for M&A and regional splits but is useful "
                        f"intel: the org runs >1 Entra tenant. Repeat the recon against this tenant."
                    ),
                    data={"sibling_domain": domain, "sibling_tenant_id": tid,
                          "primary_tenant_id": snap.tenant_id},
                    tags=[ChainTag.TENANT_DOMAINS_ENUMERATED],
                ))
        except Exception:
            pass

    await asyncio.gather(*(reverse_lookup(d) for d in candidates[:20]))

    return findings
