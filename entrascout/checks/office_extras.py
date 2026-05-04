"""Phase 45 — Office product extras (OneNote shared, Office Online, Lists,
Clipchamp, Microsoft Editor, Microsoft Forms quizzes/polls)."""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, is_existence_signal


# (label, url_template, why)
PROBES = [
    ("OneNote Online (shared notebooks via OneDrive)",
     "https://onedrive.live.com",
     "Universal landing. Tenant-scoped notebook sharing happens via SP/OD (covered)."),
    ("Office Online launch",
     "https://office.com/launch/?tid={tid}",
     "Auth-gated tenant deep-link to Office Online."),
    ("Microsoft Lists consumer (lists.live.com)",
     "https://lists.live.com",
     "Consumer Lists — separate from SP. Mixed-account leakage potential."),
    ("Microsoft Clipchamp",
     "https://app.clipchamp.com",
     "Universal video editor. Tenant content is per-user."),
    ("Microsoft Editor",
     "https://editor.microsoft.com",
     "Universal."),
    ("Microsoft Forms classic launching landing",
     "https://forms.office.com/Pages/landing.aspx?tid={tid}",
     "Auth-gated, tenant deep-link (already partial in ms_public_content)."),
    ("Microsoft Search admin (Bing for Business)",
     "https://www.bing.com/business/explore?tid={tid}",
     "Auth-gated tenant deep-link."),
    ("OneDrive personal universal entry",
     "https://onedrive.live.com/about",
     "Universal."),
]


async def probe(http: StealthClient, url: str) -> int | None:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    return r.status_code if r else None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand
    tid = snap.tenant_id or ""

    sem = asyncio.Semaphore(min(ctx.workers, 8))

    async def go(label: str, tpl: str, why: str) -> None:
        url = (tpl.replace("{tenant}", tenant_short)
                  .replace("{brand}", brand)
                  .replace("{tid}", tid))
        async with sem:
            code = await probe(http, url)
        if code and is_existence_signal(code):
            findings.append(data(
                phase="office_extras", check="office_extra_surface",
                title=f"Office product surface: {label}",
                target=url, confidence=Confidence.LOW,
                payload={"label": label, "url": url, "status": code, "why": why},
            ))

    await asyncio.gather(*(go(lbl, tpl, why) for lbl, tpl, why in PROBES))

    return findings
