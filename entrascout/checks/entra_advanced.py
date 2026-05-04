"""Phase 43 — Entra advanced surfaces.

- Microsoft Entra External ID (newer than B2C)
- Microsoft Entra Verified ID (DID issuer URLs)
- Microsoft Entra Workload Identities (beta API)
- Microsoft Entra ID Governance (entitlement mgmt URL)
- Microsoft Entra Permissions Management (CloudKnox legacy)
- Microsoft Entra Internet/Private Access (newer ZTNA)
- PIM (auth-gated; surfaces deep-link)
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, is_existence_signal


# (label, url_template, why)
ENTRA_PROBES = [
    ("Microsoft Entra External ID — CIAM tenant pattern",
     "https://{tenant}.ciamlogin.com",
     "Newer External ID for customers. CIAM-specific subdomain."),
    ("Microsoft Entra External ID — alt endpoint",
     "https://{tenant}.b2clogin.com",
     "B2C / External ID login surface."),
    ("Microsoft Entra Verified ID — DID issuer base",
     "https://verifiedid.did.msidentity.com/v1.0/{tid}",
     "Tenant-scoped Verified ID issuer URL."),
    ("Microsoft Entra Workload Identities API (beta)",
     "https://graph.microsoft.com/beta/applications?$filter=signInAudience+eq+'AzureADandPersonalMicrosoftAccount'",
     "Workload Identities are accessed via Graph beta. Auth required."),
    ("Microsoft Entra ID Governance — entitlement management",
     "https://portal.azure.com/?tid={tid}#blade/Microsoft_AAD_ELM/...",
     "Auth-gated deep-link."),
    ("Microsoft Entra Permissions Management (CloudKnox legacy)",
     "https://app.cloudknox.io",
     "Universal CloudKnox / Entra Permissions Management."),
    ("Microsoft Entra Internet Access (newer ZTNA)",
     "https://entra.microsoft.com/?tid={tid}#view/Microsoft_Azure_Network/InternetAccess.ReactView",
     "ZTNA replacement for App Proxy. Auth-gated."),
    ("Microsoft Entra Private Access (newer ZTNA)",
     "https://entra.microsoft.com/?tid={tid}#view/Microsoft_Azure_Network/PrivateAccess.ReactView",
     "Replacement for App Proxy. Auth-gated."),
    ("Microsoft Entra PIM admin",
     "https://portal.azure.com/?tid={tid}#blade/Microsoft_Azure_PIMCommon/CommonMenuBlade",
     "PIM admin deep-link. Auth-gated."),
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

    async def go(label: str, tpl: str, why: str) -> None:
        url = (tpl.replace("{tenant}", tenant_short)
                  .replace("{brand}", brand)
                  .replace("{tid}", tid))
        async with sem:
            code = await probe(http, url)
        if code and is_existence_signal(code):
            findings.append(data(
                phase="entra_advanced", check="entra_advanced_surface",
                title=f"Entra advanced surface: {label}",
                target=url, confidence=Confidence.MEDIUM,
                payload={"label": label, "url": url, "status": code, "why": why},
            ))

    await asyncio.gather(*(go(lbl, tpl, why) for lbl, tpl, why in ENTRA_PROBES))

    # ---- External ID OIDC discovery (the most useful) ----
    if tenant_short:
        ext_url = f"https://{tenant_short}.ciamlogin.com/{tenant_short}.onmicrosoft.com/v2.0/.well-known/openid-configuration"
        r = await http.get(ext_url)
        if r and r.status_code == 200:
            findings.append(lead(
                phase="entra_advanced", check="external_id_tenant_detected",
                title=f"Microsoft Entra External ID tenant detected: {tenant_short}.ciamlogin.com",
                target=ext_url, severity=Severity.LOW, confidence=Confidence.HIGH,
                description=(
                    "Tenant runs Microsoft Entra External ID (newer customer-identity service "
                    "replacing B2C). Different attack surface than B2B Entra: custom user "
                    "flows, social IdP federation, custom HTML branding."
                ),
                data={"url": ext_url, "tenant_short": tenant_short},
                tags=[ChainTag.AAD_B2C_TENANT],
            ))

    return findings
