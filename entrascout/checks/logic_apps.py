"""Phase 19 — Logic App / Power Automate trigger URL hunting (gap #7).

Logic App "When HTTP request received" triggers expose SAS URLs:

    https://prod-XX.{region}.logic.azure.com/workflows/{guid}/triggers/manual/paths/invoke?
        api-version=2016-10-01&sp=/triggers/manual/run&sv=1.0&sig=...

These URLs grant remote execution into a Logic App. They commonly leak in:
- Public GitHub repos
- Postman collections shared as Gists
- Stack Overflow answers
- WebHook libraries on Power Platform community sites

This check builds a dork pack (also returned as a finding for downstream
GitHub-search execution by the github_dorks module) and probes Logic-App
hostnames against the brand to confirm regional usage.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


# Logic App regional prod- prefixes (sample of common ones)
LOGIC_APP_REGIONS = [
    "prod-00", "prod-01", "prod-02", "prod-05", "prod-07", "prod-12",
    "prod-15", "prod-20", "prod-29", "prod-50",
]
LOGIC_APP_DOMAINS = [
    "westeurope.logic.azure.com",
    "eastus.logic.azure.com",
    "westus.logic.azure.com",
    "northeurope.logic.azure.com",
    "centralus.logic.azure.com",
    "uksouth.logic.azure.com",
    "australiaeast.logic.azure.com",
    "japaneast.logic.azure.com",
]


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]

    # The hostnames are MULTI-TENANT — every Logic App in a region shares a host.
    # Existence of the host doesn't mean the tenant uses Logic Apps. So we just
    # emit a hunt-pack: the dorks to run + sample URL pattern for awareness.
    findings.append(data(
        phase="logic_apps", check="logic_app_trigger_hunt_pack",
        title="Logic App trigger URL hunt pack — patterns to search in repos / Postman / Slack archives",
        target="https://logic.azure.com/", confidence=Confidence.HIGH,
        payload={
            "url_pattern": "https://prod-NN.{region}.logic.azure.com/workflows/{guid}/triggers/manual/paths/invoke?api-version=...&sp=...&sig=...",
            "github_dorks": [
                f'"{brand}" "logic.azure.com" "triggers/manual"',
                f'"{brand}" "/workflows/" "/triggers/manual/paths/invoke"',
                f'"logic.azure.com" "sp=%2Ftriggers%2Fmanual%2Frun" {brand}',
            ],
            "postman_search": f'https://www.postman.com/explore?term=logic.azure.com {brand}',
            "regions": LOGIC_APP_REGIONS,
            "domains": LOGIC_APP_DOMAINS,
            "impact": "Each leaked trigger URL == anonymous remote-execution into the Logic App. Treat as a P2/P3.",
        },
        tags=[ChainTag.AZ_LOGIC_APP_TRIGGER],
    ))

    return findings
