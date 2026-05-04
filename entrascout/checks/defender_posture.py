"""Phase 26 — Defender / MCAS / Sentinel / MIP posture probes (gaps #14, #20, #24, #25).

Hunts for:
- MCAS portal URL: {tenant}.portal.cloudappsecurity.com
- Sentinel public workbook leak (PowerBI URL pattern with workspace ID)
- Defender XDR / SOAR webhook leak hunt-pack (GitHub dorks for *.security.microsoft.com webhooks)
- MIP sensitivity-label exposure (mostly out-of-band; emits hunt guidance)

Mostly existence + dork-pack output (paid recon path).
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, is_existence_signal


MCAS_REGIONS = ["", ".eu", ".eu2", ".us2", ".us3", ".us"]


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand

    sem = asyncio.Semaphore(min(ctx.workers, 6))

    # ---- MCAS portal: {tenant}.portal.cloudappsecurity.com ----
    async def mcas_probe(region: str) -> None:
        host = f"{tenant_short}{region}.portal.cloudappsecurity.com"
        url = f"https://{host}"
        async with sem:
            r = await http.head(url)
            if not r:
                r = await http.get(url)
        if r and is_existence_signal(r.status_code):
            findings.append(data(
                phase="defender_posture", check="mcas_portal_exists",
                title=f"MCAS / Defender for Cloud Apps portal exists: {url}",
                target=url, confidence=Confidence.HIGH,
                payload={"url": url, "host": host, "region_suffix": region or "(default)",
                         "status": r.status_code,
                         "interpretation": "Tenant has MCAS licensed (defensive posture signal)."},
                tags=[ChainTag.MCAS_TENANT],
            ))

    if tenant_short:
        await asyncio.gather(*(mcas_probe(r) for r in MCAS_REGIONS))

    # ---- Defender / SOAR webhook hunt-pack (no direct probe — emit dorks) ----
    findings.append(data(
        phase="defender_posture", check="defender_soar_webhook_hunt_pack",
        title="Defender XDR / Sentinel SOAR webhook leak — GitHub / public-search dork pack",
        target="https://security.microsoft.com", confidence=Confidence.HIGH,
        payload={
            "github_dorks": [
                f'"{brand}" "security.microsoft.com" webhook',
                f'"{brand}" "outlook.office.com/webhook"',
                f'"{brand}" "westeurope.logic.azure.com" "Sentinel"',
                f'"sentinel" "{brand}" "playbook" "/webhooks/"',
            ],
            "impact": "Leaked SOAR webhook URL = attacker can trigger incident-response workflows on demand (reset MFA, send notifications, modify rules).",
        },
        tags=[ChainTag.DEFENDER_LEAK],
    ))

    # ---- MIP sensitivity-label hunt-pack ----
    findings.append(data(
        phase="defender_posture", check="mip_sensitivity_label_hunt",
        title="MIP / sensitivity-label hunting guidance",
        target=apex, confidence=Confidence.MEDIUM,
        payload={
            "approach": [
                "MIP labels live in document metadata. Public docs from the tenant may carry MIP property tags (`MSIP_Label_*`) that reveal the org's classification taxonomy.",
                "Pull a sample of public PDFs/DOCX from the org website, run `exiftool` and grep for `MSIP_Label`.",
                "Knowing internal label names helps an attacker craft phish that mimics legit classification banners.",
            ],
            "exiftool_filter": "exiftool -a -G1 -*MSIP* file.pdf",
        },
        tags=[ChainTag.MIP_LABEL_LEAK],
    ))

    # ---- Sentinel public-workbook leak: rare but high-value ----
    # Workbook URLs follow https://portal.azure.com/#asset/Microsoft_Azure_Monitoring/Workbook/...
    # which always require auth. The leak vector is an org publishing a Workbook ARM template
    # to a public repo with the LAW (Log Analytics Workspace) ID embedded.
    findings.append(data(
        phase="defender_posture", check="sentinel_workbook_hunt_pack",
        title="Sentinel workbook ARM-template hunt pack",
        target="https://portal.azure.com/", confidence=Confidence.MEDIUM,
        payload={
            "github_dorks": [
                f'"{brand}" "kind: shared" "/workbooks/" "Microsoft.Insights"',
                f'"{brand}" "OperationalInsights/workspaces" workspaceId',
                f'"{brand}" "logAnalytics" workspaceId',
            ],
            "impact": "Leaked LAW workspace ID + workbook structure reveals detection coverage (defender intel).",
        },
        tags=[ChainTag.DEFENDER_LEAK],
    ))

    return findings
