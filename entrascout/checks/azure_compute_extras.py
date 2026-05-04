"""Phase 38 — Azure compute extras (AKS, Service Fabric, Batch, Spring, ACI, Lab Services)."""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, issue, lead


# Region prefixes for region-scoped services
REGIONS = ["westeurope", "eastus", "westus", "northeurope", "centralus",
           "uksouth", "australiaeast", "japaneast", "eastus2", "westus2",
           "southeastasia", "francecentral", "germanywestcentral"]


def variants(brand: str) -> list[str]:
    if not brand or len(brand) < 3:
        return []
    return list(dict.fromkeys([
        brand, f"{brand}-aks", f"{brand}aks", f"{brand}-prod", f"{brand}-cluster",
        f"{brand}k8s", f"{brand}-k8s",
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

    # ---- AKS public API server: {name}-{hash}.{region}.azmk8s.io ----
    # The hash makes pure brute infeasible. Probe the apex pattern + check /healthz.
    async def aks(name: str, region: str) -> None:
        # Try without hash (rare but happens for older clusters)
        url = f"https://{name}.{region}.azmk8s.io"
        code = await probe_url(http, url, sem)
        if code in (200, 401, 403):
            # Probe /healthz which is anonymous on most AKS clusters
            healthz = f"{url}/healthz"
            async with sem:
                r = await http.get(healthz)
            healthy = r and r.status_code == 200 and "ok" in (r.text or "").lower()
            sev = Severity.MEDIUM if healthy else Severity.LOW
            findings.append(lead(
                phase="azure_compute_extras", check="aks_api_server",
                title=f"AKS API server reachable: {url}{' (anonymous /healthz)' if healthy else ''}",
                target=url, severity=sev, confidence=Confidence.HIGH,
                description=(
                    "Azure Kubernetes Service public API server endpoint detected. "
                    + ("Anonymous /healthz indicates the API is internet-reachable. "
                       "Audit kube-apiserver authorization config and consider "
                       "restricting to authorized IP ranges." if healthy else
                       "Auth-gated; recon signal.")
                ),
                data={"url": url, "name": name, "region": region, "status": code,
                      "healthz_anonymous": bool(healthy)},
            ))

    for n in variants(brand)[:3]:
        await asyncio.gather(*(aks(n, r) for r in REGIONS[:6]))

    # ---- Azure Batch: {name}.{region}.batch.azure.com ----
    async def batch(name: str, region: str) -> None:
        url = f"https://{name}.{region}.batch.azure.com"
        code = await probe_url(http, url, sem)
        if code in (200, 401, 403):
            findings.append(lead(
                phase="azure_compute_extras", check="azure_batch_account",
                title=f"Azure Batch account reachable: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                data={"url": url, "name": name, "region": region, "status": code},
            ))

    for n in variants(brand)[:3]:
        await asyncio.gather(*(batch(n, r) for r in REGIONS[:6]))

    # ---- Spring Apps: {name}.azuremicroservices.io (legacy) / .azurecontainerapps.io ----
    async def spring(name: str) -> None:
        for suffix in ("azuremicroservices.io",):
            url = f"https://{name}.{suffix}"
            code = await probe_url(http, url, sem)
            if code in (200, 401, 403, 301, 302):
                findings.append(lead(
                    phase="azure_compute_extras", check="azure_spring_apps",
                    title=f"Azure Spring Apps endpoint: {url}",
                    target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                    data={"url": url, "name": name, "status": code},
                ))

    for n in variants(brand)[:3]:
        await spring(n)

    # ---- Azure Lab Services: {name}.labs.azure.com ----
    async def lab(name: str) -> None:
        url = f"https://{name}.labs.azure.com"
        code = await probe_url(http, url, sem)
        if code in (200, 301, 302, 401, 403):
            findings.append(lead(
                phase="azure_compute_extras", check="azure_lab_services",
                title=f"Azure Lab Services endpoint: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                data={"url": url, "name": name, "status": code},
            ))

    for n in variants(brand)[:3]:
        await lab(n)

    return findings
