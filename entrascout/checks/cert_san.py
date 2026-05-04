"""Phase 28 — Power Pages / brand cert SAN sweep (gap #23).

For each Power Pages portal we found, plus the apex login URL pattern, pull the
TLS certificate's SAN list from crt.sh (Certificate Transparency) and see if
it discloses additional related hostnames (other portals, sibling brands,
internal-test FQDNs accidentally on the same cert).
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


async def crtsh_query(http: StealthClient, q: str) -> list[dict]:
    url = f"https://crt.sh/?q={q}&output=json"
    r = await http.get(url)
    if not r or r.status_code != 200:
        return []
    try:
        return r.json() or []
    except Exception:
        return []


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]

    # Build targets: apex, *.apex (CT log), and any Power Pages portals from prior findings.
    targets: list[str] = [apex, f"%.{apex}"]
    for f in om.findings:
        if "powerappsportals.com" in (f.target or ""):
            t = (f.target or "").replace("https://", "").replace("http://", "").split("/")[0]
            if t and t not in targets:
                targets.append(t)

    seen_names: set[str] = set()
    sem = asyncio.Semaphore(min(ctx.workers, 4))

    async def query(t: str) -> None:
        async with sem:
            data_rows = await crtsh_query(http, t)
        if not data_rows:
            return
        names: set[str] = set()
        for row in data_rows[:200]:
            cn = (row.get("common_name") or "").lower()
            sans = (row.get("name_value") or "").lower().splitlines()
            for n in [cn] + sans:
                n = n.strip()
                if n and "*" not in n and len(n) < 100:
                    names.add(n)
        new = names - seen_names
        if new:
            findings.append(data(
                phase="cert_san", check="crtsh_san_sweep",
                title=f"crt.sh CT-log sweep for `{t}` — {len(new)} unique names",
                target=f"https://crt.sh/?q={t}", confidence=Confidence.HIGH,
                payload={"query": t, "unique_names": sorted(new)[:200], "count": len(new)},
                tags=[ChainTag.CERT_SAN_LEAK],
            ))
            seen_names.update(new)

    await asyncio.gather(*(query(t) for t in targets[:5]))

    return findings
