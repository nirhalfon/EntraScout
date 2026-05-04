"""Phase 11 — Microsoft Copilot ecosystem detection."""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, is_existence_signal, lead


async def head_existence(http: StealthClient, url: str) -> int | None:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    return r.status_code if r else None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    domain = snap.primary_domain or ctx.target
    tenant_id = snap.tenant_id

    # M365 Copilot tenant landing
    if tenant_id:
        url = f"https://copilot.cloud.microsoft/?tenantId={tenant_id}"
        code = await head_existence(http, url)
        if code and is_existence_signal(code):
            findings.append(lead(
                phase="copilot", check="m365_copilot_tenant",
                title="M365 Copilot tenant landing page resolves",
                target=url, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                description="copilot.cloud.microsoft accepts the tenant ID — likely tenant has Copilot for M365 enabled.",
                data={"url": url, "status": code, "service": "M365 Copilot"},
                tags=[ChainTag.PP_COPILOT_M365],
            ))

    # Copilot Studio (formerly PVA)
    studio_url = "https://copilotstudio.microsoft.com/"
    code = await head_existence(http, studio_url)
    if code and is_existence_signal(code):
        findings.append(data(
            phase="copilot", check="copilot_studio_reachable",
            title="Copilot Studio frontend reachable (global, not tenant-specific)",
            target=studio_url, confidence=Confidence.HIGH,
            payload={"url": studio_url, "status": code, "service": "Copilot Studio"},
            tags=[ChainTag.PP_COPILOT_STUDIO],
        ))

    # Pointer to power-pwn for deep enum
    findings.append(lead(
        phase="copilot", check="powerpwn_handoff",
        title="Use power-pwn for deep Copilot Studio bot enumeration",
        target=ctx.target, severity=Severity.LOW, confidence=Confidence.HIGH,
        description=(
            "Custom-published Copilot Studio bots can be enumerated with mbrg/power-pwn "
            "(`copilot-studio-hunter` mode). Anonymously-accessible bots are a prompt-injection / data-exfil vector."
        ),
        recommendation="Run: `pipx install power-pwn` and `power-pwn copilot-studio-hunter --domain <domain>`.",
        tags=[ChainTag.PP_COPILOT_STUDIO],
    ))

    return findings
