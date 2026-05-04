"""Phase 42 — Dynamics 365 / Power Pages deep recon.

- D365 CRM Web API direct OData enum (`/api/data/v9.2`) — for each detected
  CRM org, probe the universal Web API base for anonymous access
- Power Pages custom-domain CNAME chasing — when a Power Pages portal is
  detected, follow CNAME to identify the vanity domain
- AppSource publisher page — `appsource.microsoft.com/marketplace/publisher/{org}`
- Power Virtual Agents bot URLs
"""
from __future__ import annotations

import asyncio

from ..dns_client import query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, issue


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]

    sem = asyncio.Semaphore(min(ctx.workers, 6))

    # ---- D365 CRM Web API direct probe — for each prior dynamics_* finding ----
    crm_hosts: set[str] = set()
    portal_hosts: set[str] = set()
    for f in om.findings:
        target = (f.target or "").lower()
        check = (f.check or "").lower()
        if "dynamics.com" in target and check.startswith("dynamics"):
            host = target.replace("https://", "").replace("http://", "").split("/")[0]
            crm_hosts.add(host)
        if "powerappsportals.com" in target:
            host = target.replace("https://", "").replace("http://", "").split("/")[0]
            portal_hosts.add(host)

    async def crm_api(host: str) -> None:
        url = f"https://{host}/api/data/v9.2/"
        async with sem:
            r = await http.get(url, headers={"Accept": "application/json"})
        if not r:
            return
        if r.status_code == 200 and "value" in (r.text or ""):
            findings.append(issue(
                phase="dynamics_deep", check="d365_webapi_anonymous",
                title=f"D365 Web API responds 200 anonymously: {url}",
                target=url, severity=Severity.HIGH, confidence=Confidence.HIGH,
                description="D365 CRM Web API returned 200 to an anonymous request — "
                            "should always be auth-gated. Investigate which entities are exposed.",
                data={"url": url, "host": host, "status": r.status_code,
                      "response_snippet": (r.text or "")[:500]},
                tags=[ChainTag.PP_DYNAMICS_ORG],
            ))
        elif r.status_code in (401, 403):
            findings.append(data(
                phase="dynamics_deep", check="d365_webapi_auth_gated",
                title=f"D365 Web API auth-gated: {url}",
                target=url, confidence=Confidence.HIGH,
                payload={"url": url, "host": host, "status": r.status_code},
            ))

    if crm_hosts:
        await asyncio.gather(*(crm_api(h) for h in list(crm_hosts)[:5]))

    # ---- Power Pages custom-domain CNAME chase ----
    # For each portal, look up its CNAME chain — many orgs proxy with a vanity domain.
    # Reverse-lookup harder; instead, probe common patterns under the apex.
    common_portal_subs = ["portal", "support", "customer", "partner", "vendor",
                          "self-service", "selfservice", "register", "apply",
                          "{brand}-portal", "{brand}-support"]
    for tpl in common_portal_subs:
        sub = tpl.replace("{brand}", brand)
        host = f"{sub}.{apex}"
        try:
            cnames = await query(host, "CNAME", timeout=4.0)
        except Exception:
            cnames = []
        for c in cnames:
            if "powerappsportals.com" in c.lower():
                findings.append(lead(
                    phase="dynamics_deep", check="power_pages_vanity_domain",
                    title=f"Power Pages portal behind vanity domain: {host} → {c}",
                    target=f"https://{host}",
                    severity=Severity.LOW, confidence=Confidence.HIGH,
                    description="A subdomain of the org CNAMEs to a Power Pages portal. "
                                "Audit the portal's anonymous-access policies; the vanity "
                                "domain often masks the real Dataverse OData endpoint.",
                    data={"vanity_host": host, "portal_target": c.rstrip(".")},
                    tags=[ChainTag.PP_POWER_PAGES],
                ))

    # ---- AppSource publisher ----
    pub_url = f"https://appsource.microsoft.com/en-us/marketplace/publisher/{brand}"
    r = await http.head(pub_url)
    if not r:
        r = await http.get(pub_url)
    if r and r.status_code in (200, 301, 302):
        findings.append(data(
            phase="dynamics_deep", check="appsource_publisher",
            title=f"AppSource publisher page exists: {pub_url}",
            target=pub_url, confidence=Confidence.MEDIUM,
            payload={"url": pub_url, "status": r.status_code,
                     "interpretation": "Org publishes apps to AppSource — check listed apps for security postures."},
        ))

    return findings
