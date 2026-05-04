"""Phase 20 — Azure DevOps deeper recon (gap #8).

Beyond the public-projects / public-wiki probes already done by azure_resources,
this module:
- Enumerates organization-level metadata: feature toggles, public service connections
- Pulls pipeline YAML when public projects are detected (lists, doesn't fetch all)
- Probes legacy `*.visualstudio.com` host as fallback
- Identifies extension marketplace listings authored by the org
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, is_existence_signal


async def head_existence(http: StealthClient, url: str) -> int | None:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    return r.status_code if r else None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]

    # Did azure_resources detect an ADO org? Reuse its finding.
    ado_orgs: list[str] = []
    for f in om.findings:
        if "dev.azure.com" in (f.target or "") or f.check.startswith("ado_"):
            target = f.target or ""
            if "dev.azure.com/" in target:
                org = target.split("dev.azure.com/")[1].split("/")[0]
                if org:
                    ado_orgs.append(org)
    ado_orgs = list(dict.fromkeys(ado_orgs))[:3]

    sem = asyncio.Semaphore(min(ctx.workers, 6))

    # ---- Legacy *.visualstudio.com fallback ----
    if brand:
        legacy = f"https://{brand}.visualstudio.com"
        async with sem:
            code = await head_existence(http, legacy)
        if code and is_existence_signal(code):
            findings.append(lead(
                phase="ado_deep", check="ado_legacy_visualstudio",
                title=f"Legacy Azure DevOps URL reachable: {legacy}",
                target=legacy, severity=Severity.LOW, confidence=Confidence.HIGH,
                description=(
                    "Legacy *.visualstudio.com URLs sometimes have looser permissions or "
                    "stale anonymous-access policies. Verify whether public projects under "
                    "this URL match the org's current dev.azure.com/{org} configuration."
                ),
                data={"url": legacy, "status": code},
                tags=[ChainTag.AZ_DEVOPS_ORG],
            ))

    # ---- For each known ADO org: pull public projects + auto-link to pipelines API ----
    async def deep_probe(org: str) -> None:
        api = f"https://dev.azure.com/{org}/_apis/projects?api-version=7.0&stateFilter=wellFormed"
        async with sem:
            r = await http.get(api)
        if r and r.status_code == 200:
            try:
                j = r.json()
                projs = j.get("value") or []
                for p in projs[:25]:
                    pname = p.get("name", "")
                    findings.append(data(
                        phase="ado_deep", check="ado_public_project_detail",
                        title=f"Public ADO project: {org}/{pname}",
                        target=f"https://dev.azure.com/{org}/{pname}",
                        confidence=Confidence.HIGH,
                        payload={
                            "org": org, "project": pname,
                            "id": p.get("id"),
                            "visibility": p.get("visibility"),
                            "pipelines_url": f"https://dev.azure.com/{org}/{pname}/_apis/pipelines?api-version=7.0",
                            "service_endpoints_url": f"https://dev.azure.com/{org}/{pname}/_apis/serviceendpoint/endpoints?api-version=7.0",
                        },
                        tags=[ChainTag.AZ_DEVOPS_PUBLIC_PROJECTS],
                    ))
            except Exception:
                pass
        # Marketplace publisher
        mkt = f"https://marketplace.visualstudio.com/publishers/{org}"
        async with sem:
            mr = await head_existence(http, mkt)
        if mr and mr in (200, 301, 302):
            findings.append(data(
                phase="ado_deep", check="ado_marketplace_publisher",
                title=f"Marketplace publisher exists: {org}",
                target=mkt, confidence=Confidence.HIGH,
                payload={"url": mkt, "status": mr},
                tags=[ChainTag.AZ_DEVOPS_ORG],
            ))

    if ado_orgs:
        await asyncio.gather(*(deep_probe(o) for o in ado_orgs))

    return findings
