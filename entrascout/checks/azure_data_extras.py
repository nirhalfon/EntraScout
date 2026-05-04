"""Phase 39 — Azure data-platform extras (Synapse, Data Factory, Databricks,
HDInsight, ML, AI Foundry, Health Bot, FHIR, Confidential Ledger)."""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


REGIONS = ["westeurope", "eastus", "westus", "northeurope", "centralus",
           "uksouth", "australiaeast", "japaneast", "eastus2", "westus2"]


# (suffix, label, expected_codes)
DIRECT_PROBES = [
    # Synapse — workspace at {ws}.dev.azuresynapse.net + {ws}.sql.azuresynapse.net
    ("dev.azuresynapse.net", "Azure Synapse Studio", (200, 401, 403)),
    ("sql.azuresynapse.net", "Azure Synapse SQL endpoint", (200, 401, 403, 1433)),
    # HDInsight
    ("azurehdinsight.net", "Azure HDInsight cluster", (200, 401, 403)),
    # Health Bot
    ("healthbot.microsoft.com", "Azure Health Bot", (200, 301, 302, 401, 403, 404)),
    # Confidential Ledger
    ("confidential-ledger.azure.com", "Azure Confidential Ledger", (200, 401, 403)),
    # FHIR
    ("fhir.azurehealthcareapis.com", "Azure API for FHIR", (200, 401, 403)),
    # Cognitive sub-services
    ("cognitiveservices.azure.com", "Azure Cognitive Services", (200, 401, 403)),
]


def variants(brand: str) -> list[str]:
    if not brand or len(brand) < 3:
        return []
    return list(dict.fromkeys([
        brand, f"{brand}-prod", f"{brand}-data", f"{brand}-dwh",
        f"{brand}-ml", f"{brand}-aml", f"{brand}-ai",
    ]))


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

    async def probe(name: str, suffix: str, label: str, expected: tuple) -> None:
        url = f"https://{name}.{suffix}"
        code = await probe_url(http, url, sem)
        if code and code in expected and code != 404:
            findings.append(lead(
                phase="azure_data_extras", check=f"{suffix.split('.')[0]}_endpoint",
                title=f"{label}: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                data={"url": url, "name": name, "suffix": suffix, "status": code, "label": label},
            ))

    for n in variants(brand):
        await asyncio.gather(*(probe(n, suf, lbl, exp) for suf, lbl, exp in DIRECT_PROBES))

    # ---- Databricks: adb-{numeric_id}.{n}.azuredatabricks.net — needs ID ----
    # Numeric IDs aren't brute-forceable; just probe the universal control plane
    async def db_universal(region: str) -> None:
        url = f"https://{region}.azuredatabricks.net"
        code = await probe_url(http, url, sem)
        if code in (200, 301, 302, 401, 403):
            findings.append(data(
                phase="azure_data_extras", check="databricks_region_reachable",
                title=f"Databricks region endpoint reachable: {url} (universal — only confirms region)",
                target=url, confidence=Confidence.LOW,
                payload={"url": url, "region": region, "status": code,
                         "note": "Tenant-scoped Databricks workspace IDs are numeric and not brute-forceable; "
                                 "use GitHub-dork hunting for `adb-*.azuredatabricks.net {brand}`."},
            ))

    # Skip per-region universal probe (too noisy); just emit the dork
    findings.append(data(
        phase="azure_data_extras", check="databricks_workspace_dork",
        title="Databricks workspace ID hunt-pack (numeric ID required)",
        target="https://*.azuredatabricks.net", confidence=Confidence.HIGH,
        payload={
            "github_dorks": [
                f'"{brand}" "adb-" "azuredatabricks.net"',
                f'"{brand}" "databricks_token"',
                f'"{brand}" "https://adb-"',
            ],
            "note": "Databricks workspace URLs follow https://adb-{numeric_id}.{n}.azuredatabricks.net. "
                    "ID is not brute-forceable; hunt via GitHub / Stack Overflow / Postman.",
        },
    ))

    # ---- Data Factory: {name}.{region}.datafactory.azure.com ----
    async def adf(name: str, region: str) -> None:
        url = f"https://{name}.{region}.datafactory.azure.com"
        code = await probe_url(http, url, sem)
        if code in (200, 401, 403):
            findings.append(lead(
                phase="azure_data_extras", check="data_factory_endpoint",
                title=f"Azure Data Factory: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                data={"url": url, "name": name, "region": region, "status": code},
            ))

    for n in variants(brand)[:3]:
        await asyncio.gather(*(adf(n, r) for r in REGIONS[:5]))

    # ---- Azure Machine Learning: {name}.{region}.api.azureml.ms ----
    async def aml(name: str, region: str) -> None:
        url = f"https://{name}.{region}.api.azureml.ms"
        code = await probe_url(http, url, sem)
        if code in (200, 401, 403):
            findings.append(lead(
                phase="azure_data_extras", check="aml_workspace_endpoint",
                title=f"Azure ML workspace: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                data={"url": url, "name": name, "region": region, "status": code},
            ))

    for n in variants(brand)[:3]:
        await asyncio.gather(*(aml(n, r) for r in REGIONS[:5]))

    return findings
