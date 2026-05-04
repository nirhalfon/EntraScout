"""Phase 50 — Power Pages OData entity-set deep probe.

Beyond `/_odata/$metadata`, probe specific common entity sets directly:
- /_odata/contacts
- /_odata/accounts
- /_odata/incidents (cases)
- /_odata/cr*_* (custom Dataverse tables)

Sometimes individual entity sets are queryable even when $metadata is gated.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, issue


# Common Dataverse entity sets exposed via Power Pages OData
COMMON_ENTITY_SETS = [
    "contacts", "accounts", "incidents", "cases",
    "leads", "opportunities", "products", "subjects",
    "annotations", "activities", "appointments",
    "feedback", "reviews", "ratings",
    "users", "systemusers",
    "queues", "teams",
    "knowledgearticles", "knowledgebaserecords",
    # Public Power Pages-specific
    "powerpagesite", "adx_blogposts", "adx_webfiles",
    "adx_pollchoices", "adx_polls", "adx_publishingstates",
    "msdyn_kbarticleimages",
]


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []

    portal_urls: set[str] = set()
    for f in om.findings:
        target = (f.target or "")
        if "powerappsportals.com" in target and target.startswith("https://"):
            base = target.replace("https://", "").split("/")[0]
            portal_urls.add(f"https://{base}")
        if "vanity_host" in (f.data or {}):
            portal_urls.add(f"https://{(f.data or {}).get('vanity_host')}")
    portal_urls_list = list(portal_urls)[:5]

    if not portal_urls_list:
        return findings

    sem = asyncio.Semaphore(min(ctx.workers, 8))

    async def probe(base: str, entity: str) -> None:
        url = f"{base}/_odata/{entity}?$top=1"
        async with sem:
            r = await http.get(url, headers={"Accept": "application/json"})
        if not r:
            return
        # 200 with JSON body containing "value" array = anonymous entity readable
        if r.status_code == 200 and ("value" in (r.text or "") or "@odata.context" in (r.text or "")):
            findings.append(issue(
                phase="power_pages_odata_deep", check="odata_entity_anonymous",
                title=f"Power Pages OData entity readable anonymously: {url}",
                target=url, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description=(
                    f"Power Pages OData endpoint /_odata/{entity} returned 200 with data "
                    f"to an anonymous request. This is a Dataverse data-disclosure misconfig — "
                    f"the entity has anonymous Read permission via Web Role / Table Permissions. "
                    f"Audit Power Pages 'Web Roles' and 'Table Permissions' — strip anonymous "
                    f"read on this entity."
                ),
                data={"url": url, "entity": entity, "base": base, "status": r.status_code,
                      "snippet": (r.text or "")[:500]},
                tags=[ChainTag.PP_POWER_PAGES_ODATA],
                recommendation="Remove anonymous Read permission for this Dataverse entity in Power Pages.",
            ))
        elif r.status_code in (301, 302) and "loginredirect" in (r.headers.get("location", "")).lower():
            # auth-gated — fine
            pass

    for base in portal_urls_list:
        await asyncio.gather(*(probe(base, e) for e in COMMON_ENTITY_SETS))

    return findings
