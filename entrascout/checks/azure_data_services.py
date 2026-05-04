"""Phase 30 — Azure data services namespace enumeration.

Probes Azure data-plane resources by brand-derived namespace:
- SQL Database (`*.database.windows.net`)
- Cosmos DB (`*.documents.azure.com`)
- Cache for Redis (`*.redis.cache.windows.net`)
- Data Lake Gen2 (`*.dfs.core.windows.net`)
- Event Grid (`*.eventgrid.azure.net`)
- IoT Hub (`*.azure-devices.net`)
- Notification Hubs (`*.servicebus.windows.net`)
- Container Apps (`*.{region}.azurecontainerapps.io`)
- Static Web App preview (`{name}-{branch}.azurestaticapps.net`)
- Communication Services (`*.communication.azure.com`)
- Bot Framework (`*.botframework.com`)
- Cognitive Search (`*.search.windows.net`)
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, is_existence_signal


# Per-namespace probes:
# (name_template, suffix_domain, severity_meaning, expected_existence_codes, label, tag)
DATA_SVC_PROBES = [
    # SQL Database — server name is brand-prefixed; HTTPS to root usually 404
    # but the auth flow uses tcp/1433 — best signal is DNS resolution.
    # Direct HEAD to https://<name>.database.windows.net almost always 404 even
    # when the server exists. So we only emit guidance for SQL.
    # Cosmos DB — HEAD usually returns 401 if exists
    ("{n}", "documents.azure.com", "Cosmos DB endpoint", (200, 401, 403), "cosmos", None),
    ("{n}-cosmos", "documents.azure.com", "Cosmos DB endpoint", (200, 401, 403), "cosmos", None),
    # Redis — HEAD on the SSL port usually fails; signal is DNS resolution.
    # Skipping HTTP for redis (TLS only over 6380).
    # Data Lake Gen2 — same as blob; usually 400 InvalidUri without container
    ("{n}", "dfs.core.windows.net", "Data Lake Gen2 endpoint", (200, 400, 403), "datalake", None),
    # Event Grid topic — usually 401
    ("{n}", "eventgrid.azure.net", "Event Grid endpoint", (200, 401, 403), "eventgrid", None),
    ("{n}-grid", "eventgrid.azure.net", "Event Grid endpoint", (200, 401, 403), "eventgrid", None),
    # IoT Hub — usually 401
    ("{n}", "azure-devices.net", "IoT Hub endpoint", (200, 401), "iothub", None),
    ("{n}-iot", "azure-devices.net", "IoT Hub endpoint", (200, 401), "iothub", None),
    # Service Bus / Event Hubs / Notification Hubs — same namespace
    ("{n}", "servicebus.windows.net", "Service Bus / Event Hubs", (200, 401, 404), "servicebus", None),
    ("{n}-sb", "servicebus.windows.net", "Service Bus / Event Hubs", (200, 401, 404), "servicebus", None),
    # Communication Services
    ("{n}", "communication.azure.com", "Communication Services endpoint", (200, 401, 403), "comms", None),
    ("{n}-comm", "communication.azure.com", "Communication Services endpoint", (200, 401, 403), "comms", None),
    # Cognitive Search — `{name}.search.windows.net`
    ("{n}", "search.windows.net", "Azure Cognitive Search endpoint", (200, 401, 403), "search", None),
    ("{n}-search", "search.windows.net", "Azure Cognitive Search endpoint", (200, 401, 403), "search", None),
    # Bot Framework
    ("{n}", "botframework.com", "Azure Bot endpoint", (200, 401, 403, 404), "bot", None),
]


# Container Apps regions
CONTAINER_APP_REGIONS = [
    "westeurope", "eastus", "westus", "northeurope", "centralus",
    "uksouth", "australiaeast", "japaneast", "eastus2", "westus2",
    "southeastasia",
]


def expand_n(template: str, brand: str) -> str:
    n = template.format(n=brand)
    return n if 3 <= len(n) <= 28 and n.replace("-", "").isalnum() else ""


async def probe_url(http: StealthClient, url: str, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        r = await http.head(url)
    if not r:
        async with sem:
            r = await http.get(url)
    return r.status_code if r else None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    if "-" in brand:
        brand = brand.split("-")[0]
    if not brand or len(brand) < 3:
        return findings

    sem = asyncio.Semaphore(min(ctx.workers, 12))

    # ---- Standard data services ----
    async def probe(name_tpl: str, suffix: str, label: str, expected_codes: tuple, svc_label: str) -> None:
        name = expand_n(name_tpl, brand)
        if not name:
            return
        url = f"https://{name}.{suffix}"
        code = await probe_url(http, url, sem)
        if code and code in expected_codes:
            findings.append(lead(
                phase="azure_data_services", check=f"{svc_label}_endpoint_exists",
                title=f"{label} exists: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                description=(
                    f"Azure data-service endpoint reachable. Auth-gated; this is a "
                    f"reconnaissance signal that the tenant uses this service under "
                    f"the `{name}` namespace."
                ),
                data={"url": url, "name": name, "suffix": suffix, "status": code,
                      "service": svc_label},
            ))

    await asyncio.gather(
        *(probe(tpl, suf, lbl, codes, svc)
          for tpl, suf, lbl, codes, svc, _ in DATA_SVC_PROBES)
    )

    # ---- Container Apps: {name}.{region}.azurecontainerapps.io ----
    async def probe_container_app(region: str, name: str) -> None:
        url = f"https://{name}.{region}.azurecontainerapps.io"
        code = await probe_url(http, url, sem)
        if code in (200, 301, 302, 401, 403):
            findings.append(lead(
                phase="azure_data_services", check="container_app_exists",
                title=f"Azure Container App reachable: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                data={"url": url, "name": name, "region": region, "status": code},
            ))

    for name in (brand, f"{brand}-app", f"{brand}app", f"{brand}-prod", f"{brand}-api"):
        if 3 <= len(name) <= 28:
            await asyncio.gather(*(probe_container_app(r, name) for r in CONTAINER_APP_REGIONS))

    # ---- Static Web App preview branches ----
    # Pattern: {name}-{branch}.azurestaticapps.net
    # Common branch names trigger preview deployments
    PREVIEW_BRANCHES = ["dev", "develop", "develop-1", "staging", "stage",
                        "feature", "test", "qa", "uat", "preview", "next"]
    async def probe_swa_preview(name: str, branch: str) -> None:
        url = f"https://{name}-{branch}.azurestaticapps.net"
        code = await probe_url(http, url, sem)
        if code in (200, 301, 302):
            findings.append(lead(
                phase="azure_data_services", check="static_web_app_preview",
                title=f"Static Web App preview branch reachable: {url}",
                target=url, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description="Preview / branch deployment of a Static Web App found. "
                            "Often runs unfinished code with relaxed auth or fewer guard rails.",
                data={"url": url, "name": name, "branch": branch, "status": code},
            ))

    for name in (brand,):
        await asyncio.gather(*(probe_swa_preview(name, b) for b in PREVIEW_BRANCHES))

    return findings
