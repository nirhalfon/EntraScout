"""Phase 24 — Wayback / archive sweep (gap #15).

Queries web.archive.org for historical pages matching the tenant's branded
login pages, ADFS endpoints, and SharePoint sites. Useful for finding:
- Old federation endpoints (before key rotation)
- Deprecated subdomains that may still resolve
- Tenant ID rotations (rare but informative)
- Old branded-login backgrounds and logos that may persist on stale CDNs
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

    sem = asyncio.Semaphore(min(ctx.workers, 6))

    # CDX API endpoint for archive.org
    queries = [
        ("login_pages", f"https://web.archive.org/cdx/search/cdx?url=login.microsoftonline.com/{apex}/*&limit=20&output=json"),
        ("federation", f"https://web.archive.org/cdx/search/cdx?url=*.{apex}/adfs/*&limit=20&output=json"),
        ("sharepoint", f"https://web.archive.org/cdx/search/cdx?url=*.{apex}/sites/*&limit=20&output=json"),
        ("oneonmicrosoft", f"https://web.archive.org/cdx/search/cdx?url={apex.split('.')[0]}.onmicrosoft.com/*&limit=20&output=json"),
    ]

    async def query(label: str, url: str) -> None:
        async with sem:
            r = await http.get(url)
        if not r or r.status_code != 200:
            return
        try:
            j = r.json()
        except Exception:
            return
        if not j or len(j) <= 1:
            return
        # First row is the header; drop it
        rows = j[1:]
        sample = [{"timestamp": row[1], "url": row[2], "status": row[4]} for row in rows[:5] if len(row) > 4]
        findings.append(data(
            phase="wayback", check=f"wayback_{label}",
            title=f"Wayback archive snapshots found ({label}, {len(rows)} hits)",
            target=url, confidence=Confidence.HIGH,
            payload={"label": label, "count": len(rows), "sample": sample, "cdx_query": url},
            tags=[ChainTag.WAYBACK_HIT],
        ))

    await asyncio.gather(*(query(l, u) for l, u in queries))

    return findings
