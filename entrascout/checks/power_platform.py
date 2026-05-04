"""Phase 12 — Power Platform & Dynamics 365 detection."""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, is_existence_signal, issue, lead, validation


# Dynamics regional CRM hostnames — public commercial cloud
CRM_REGIONS = ["crm", "crm2", "crm3", "crm4", "crm5", "crm6", "crm7", "crm8", "crm9",
               "crm11", "crm12", "crm14", "crm15", "crm16", "crm17", "crm19", "crm20"]

# Sovereign / Government clouds — Dynamics 365
DYNAMICS_GOV = [
    ("crm9.dynamics.com", "DoD GCC High"),       # GCC High alt
    ("crm.microsoftdynamics.us", "GCC US Gov"),  # GCC moderate
    ("gov.microsoftdynamics.us", "GCC High US Gov"),
    ("crm.dynamics.cn", "China 21Vianet"),
    ("crm.appsplatform.us", "DoD"),              # newer DoD pattern
]

# Power Platform "make" / admin envelope hostnames — confirms Power Platform tenancy
POWER_PLATFORM_ADMIN_HOSTS = [
    "make.powerapps.com",
    "make.powerautomate.com",
    "admin.powerplatform.microsoft.com",
    "flow.microsoft.com",
]

# Dataverse environment hostname pattern — `{org}.{region}.dynamics.com`
# already covered by CRM_REGIONS. Newer pattern is `{guid}.environment.api.powerplatform.com`
# which is GUID-only and not brute-forceable; we skip.


async def head_existence(http: StealthClient, url: str) -> int | None:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    return r.status_code if r else None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand

    sem = asyncio.Semaphore(ctx.workers)

    # ---- Power Pages portals ----
    portal_url = f"https://{tenant_short}.powerappsportals.com"
    code = await head_existence(http, portal_url)
    if code and is_existence_signal(code) and code != 404:
        findings.append(data(
            phase="power_platform", check="power_pages_portal",
            title=f"Power Pages portal: {portal_url}",
            target=portal_url, confidence=Confidence.HIGH,
            payload={"service": "Power Pages", "url": portal_url, "status": code},
            tags=[ChainTag.PP_POWER_PAGES],
        ))

        # OData probe — properly check whether ANY entity sets are actually exposed.
        # 302 = auth required (NOT a leak). 200 with empty schema = no data exposed.
        # Only a 200 with at least one <EntitySet> is a real finding.
        odata_url = f"{portal_url}/_odata/$metadata"
        r = await http.get(odata_url)
        if r and r.status_code == 200 and r.text:
            entity_set_count = r.text.count('EntitySet Name=')
            if entity_set_count > 0:
                # Real leak — actual entities exposed
                findings.append(issue(
                    phase="power_platform", check="power_pages_odata_entitysets_exposed",
                    title=f"Power Pages OData exposes {entity_set_count} EntitySet(s) anonymously: {odata_url}",
                    target=odata_url, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    description=(
                        f"Power Pages OData $metadata endpoint anonymously discloses {entity_set_count} "
                        f"Dataverse EntitySet definitions. Each EntitySet may permit anonymous record "
                        f"queries (depending on Web Role / Table Permission config). Common misconfig "
                        f"that leaks Contacts, Cases, or Customer-equivalent tables."
                    ),
                    data={"url": odata_url, "entity_set_count": entity_set_count,
                          "metadata_excerpt": r.text[:2000]},
                    tags=[ChainTag.PP_POWER_PAGES_ODATA],
                    recommendation=(
                        "Audit Power Pages 'Web Roles' and 'Table Permissions' - strip anonymous read "
                        "on sensitive entities. Verify each exposed EntitySet truly needs anonymous access."
                    ),
                ))
            else:
                # 200 but empty — service configured but no data exposed
                findings.append(validation(
                    phase="power_platform", check="power_pages_odata_empty",
                    title=f"Power Pages OData configured but no entities exposed: {odata_url}",
                    target=odata_url,
                    payload={"url": odata_url, "entity_set_count": 0},
                ))
        elif r and r.status_code in (301, 302, 303):
            # Auth-gated — properly configured
            loc = r.headers.get("location", "")
            findings.append(validation(
                phase="power_platform", check="power_pages_odata_auth_gated",
                title=f"Power Pages OData auth-gated (302 to {loc[:60]}...): {odata_url}",
                target=odata_url,
                payload={"url": odata_url, "redirect": loc[:200]},
            ))

    # ---- Dynamics 365 multi-region ----
    async def probe_crm(region: str) -> None:
        url = f"https://{tenant_short}.{region}.dynamics.com"
        async with sem:
            code = await head_existence(http, url)
        if code and is_existence_signal(code) and code != 404:
            findings.append(data(
                phase="power_platform", check=f"dynamics_{region}",
                title=f"Dynamics 365 org found: {url}",
                target=url, confidence=Confidence.HIGH,
                payload={"service": "Dynamics 365", "url": url, "status": code, "region": region},
                tags=[ChainTag.PP_DYNAMICS_ORG],
            ))

    await asyncio.gather(*(probe_crm(r) for r in CRM_REGIONS))

    # ---- Sovereign / Government Dynamics clouds ----
    async def probe_gov(host_suffix: str, label: str) -> None:
        url = f"https://{tenant_short}.{host_suffix}"
        async with sem:
            code = await head_existence(http, url)
        if code and is_existence_signal(code) and code != 404:
            findings.append(data(
                phase="power_platform", check="dynamics_sovereign_cloud",
                title=f"Dynamics 365 ({label}) org found: {url}",
                target=url, confidence=Confidence.HIGH,
                payload={"service": "Dynamics 365", "url": url, "status": code,
                         "cloud": label, "host_suffix": host_suffix},
                tags=[ChainTag.PP_DYNAMICS_ORG],
            ))

    await asyncio.gather(*(probe_gov(s, lbl) for s, lbl in DYNAMICS_GOV))

    # ---- Power Platform tenancy confirmation ----
    # Probing make.powerapps.com etc. directly tells us nothing about THIS tenant
    # (they're shared MS endpoints). What's useful is the admin URL with the tenantId
    # as a query parameter — it's a deep-link that reveals tenant existence on the
    # Power Platform admin plane.
    if snap.tenant_id:
        adm_url = f"https://admin.powerplatform.microsoft.com/environments?tenantId={snap.tenant_id}"
        findings.append(data(
            phase="power_platform", check="power_platform_admin_link",
            title=f"Power Platform admin deep-link for tenant: {adm_url}",
            target=adm_url, confidence=Confidence.HIGH,
            payload={
                "service": "Power Platform Admin",
                "url": adm_url,
                "tenant_id": snap.tenant_id,
                "note": "Auth-gated; usable by any user with Power Platform admin role in this tenant.",
            },
            tags=[ChainTag.PP_DYNAMICS_ORG],
        ))

    return findings
