"""Phase 27 — NPM / PyPI / Docker Hub package leak hunt (gap #21).

Probes public package registries for entries that match the org brand prefix.
Internal packages mistakenly published are a recurring class of supply-chain
leak (npm @{org}/, pypi {org}-, docker hub user {org}).
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    if len(brand) < 3:
        return findings

    sem = asyncio.Semaphore(min(ctx.workers, 6))

    # ---- NPM scope ----
    async def npm_check() -> None:
        url = f"https://registry.npmjs.org/-/org/{brand}/package"
        async with sem:
            r = await http.get(url)
        if r and r.status_code == 200:
            try:
                j = r.json()
                pkgs = list(j.keys()) if isinstance(j, dict) else []
                if pkgs:
                    findings.append(lead(
                        phase="package_leaks", check="npm_org_packages",
                        title=f"NPM @{brand} scope contains {len(pkgs)} packages",
                        target=f"https://www.npmjs.com/org/{brand}",
                        severity=Severity.LOW, confidence=Confidence.HIGH,
                        description="Org has a public NPM scope. Audit for internal-only packages mistakenly published.",
                        data={"org": brand, "packages": pkgs[:30], "total": len(pkgs)},
                        tags=[ChainTag.PACKAGE_LEAK],
                    ))
            except Exception:
                pass

    # ---- PyPI prefix search ----
    async def pypi_check() -> None:
        url = f"https://pypi.org/simple/?prefix={brand}"
        async with sem:
            r = await http.get(url)
        if r and r.status_code == 200 and "<html" in (r.text or "").lower():
            # Find links matching the brand
            text = r.text or ""
            count = text.lower().count(f">{brand}")
            if count > 0:
                findings.append(data(
                    phase="package_leaks", check="pypi_brand_prefix_packages",
                    title=f"PyPI has packages prefixed with `{brand}` ({count} entries on first page)",
                    target=url, confidence=Confidence.MEDIUM,
                    payload={"prefix": brand, "approx_count": count, "url": url},
                    tags=[ChainTag.PACKAGE_LEAK],
                ))

    # ---- Docker Hub user/org ----
    async def docker_check() -> None:
        url = f"https://hub.docker.com/v2/repositories/{brand}/?page_size=100"
        async with sem:
            r = await http.get(url)
        if r and r.status_code == 200:
            try:
                j = r.json()
                count = j.get("count") or 0
                if count > 0:
                    repos = [it.get("name") for it in (j.get("results") or [])][:30]
                    findings.append(lead(
                        phase="package_leaks", check="dockerhub_org_repos",
                        title=f"Docker Hub `{brand}` namespace has {count} repos",
                        target=f"https://hub.docker.com/u/{brand}",
                        severity=Severity.LOW, confidence=Confidence.HIGH,
                        description="Org has a public Docker Hub presence. Audit images for embedded secrets / staging configs.",
                        data={"namespace": brand, "count": count, "sample_repos": repos},
                        tags=[ChainTag.PACKAGE_LEAK],
                    ))
            except Exception:
                pass

    await asyncio.gather(npm_check(), pypi_check(), docker_check())

    return findings
