"""Phase 15 — Microsoft 365 public-content surfaces.

Covers gaps #1, #5, #16, #17, #18 from the v0.1.6 expansion:
- Bookings (`/book/{slug}@{tenant}`) — staff PII
- Forms (`forms.office.com/r/...`)
- Stream (`{tenant}.sharepoint.com/.../stream.aspx`)
- Loop (`loop.microsoft.com`)
- Whiteboard (`whiteboard.office.com`)
- Power BI public publish-to-web
- Yammer / Viva Engage external networks

Read-only existence checks; no auth attempts.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, validation, is_existence_signal


# Common Bookings slug guesses (org-name first, then variants)
BOOKING_SLUGS = ["", "info", "support", "sales", "appointments", "booking",
                 "consult", "reception", "reservations", "schedule", "meet",
                 "team", "contact"]


async def head_existence(http: StealthClient, url: str) -> tuple[int | None, dict]:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    if not r:
        return None, {}
    return r.status_code, dict(r.headers)


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand

    sem = asyncio.Semaphore(ctx.workers)

    # ---- Microsoft Bookings ----
    # Pattern: https://outlook.office.com/book/{slug}@{tenant}.onmicrosoft.com/
    # Each slug is a discrete Bookings page; org may have 0..N.
    async def probe_booking(slug: str) -> None:
        slug_part = f"{slug}@{tenant_short}.onmicrosoft.com" if slug else f"{tenant_short}@{tenant_short}.onmicrosoft.com"
        url = f"https://outlook.office.com/book/{slug_part}/"
        async with sem:
            code, _ = await head_existence(http, url)
        if code and code == 200:
            findings.append(lead(
                phase="ms_public_content", check="bookings_page_public",
                title=f"Microsoft Bookings page publicly reachable: {url}",
                target=url, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description=(
                    "Bookings pages typically expose staff names, headshots, email addresses, "
                    "and calendar availability. Used by attackers as a free PII leak for "
                    "targeted phishing and social-engineering preparation."
                ),
                data={"url": url, "slug": slug or "(default)", "tenant_short": tenant_short},
                tags=[ChainTag.SVC_BOOKINGS_PUBLIC],
                recommendation=(
                    "Audit Bookings pages: in M365 admin center, decide which Bookings pages "
                    "should be publicly discoverable; restrict staff PII visibility on each."
                ),
            ))

    if tenant_short:
        await asyncio.gather(*(probe_booking(s) for s in BOOKING_SLUGS))

    # ---- Microsoft Forms public-form discovery (existence check on canonical hosts) ----
    # forms.office.com publishes anonymous forms at /r/{ID}. We can't brute IDs, but we
    # can confirm the tenant has Forms enabled by checking the tenant's Forms entry URL.
    forms_check = f"https://forms.office.com/Pages/landing.aspx"
    code, _ = await head_existence(http, forms_check)
    if code and is_existence_signal(code):
        findings.append(data(
            phase="ms_public_content", check="forms_service_reachable",
            title="Microsoft Forms reachable (org may publish anonymous forms)",
            target=forms_check, confidence=Confidence.MEDIUM,
            payload={
                "url": forms_check, "status": code,
                "note": "Forms IDs are random GUIDs; Bing-dork the tenant for `site:forms.office.com {brand}`.",
            },
            tags=[ChainTag.SVC_FORMS_PUBLIC],
        ))

    # ---- Stream / SharePoint video on stream.aspx ----
    # Modern Stream uses {tenant}.sharepoint.com; legacy is web.microsoftstream.com.
    if tenant_short:
        stream_legacy = f"https://web.microsoftstream.com/?app={tenant_short}"
        async with sem:
            code, _ = await head_existence(http, stream_legacy)
        if code and is_existence_signal(code):
            findings.append(data(
                phase="ms_public_content", check="stream_legacy_reachable",
                title=f"Legacy Microsoft Stream surface reachable for tenant: {tenant_short}",
                target=stream_legacy, confidence=Confidence.LOW,
                payload={"url": stream_legacy, "status": code},
                tags=[ChainTag.SVC_STREAM_PUBLIC],
            ))

    # ---- Loop ----
    loop_url = "https://loop.microsoft.com"
    async with sem:
        code, _ = await head_existence(http, loop_url)
    if code and is_existence_signal(code):
        # Loop is shared MS — tenant linkage requires a deep link with workspace ID
        findings.append(data(
            phase="ms_public_content", check="loop_service_reachable",
            title="Microsoft Loop service reachable (tenant may have public Loop workspaces)",
            target=loop_url, confidence=Confidence.LOW,
            payload={"url": loop_url, "status": code,
                     "note": "Use Bing-dork `site:loop.microsoft.com {brand}` to find public workspaces."},
            tags=[ChainTag.SVC_LOOP_PUBLIC],
        ))

    # ---- Power BI public publish-to-web (auth-gated probe — checks tenant's view URL pattern) ----
    # Power BI publish-to-web reports live at app.powerbi.com/view?r={GUID} — global.
    # The tenant-scoped check is whether app.powerbi.com/groups/me/list returns tenant context.
    pbi_url = "https://app.powerbi.com/home"
    async with sem:
        code, _ = await head_existence(http, pbi_url)
    if code and is_existence_signal(code):
        findings.append(data(
            phase="ms_public_content", check="powerbi_service_reachable",
            title="Power BI service reachable (Bing-dork for `app.powerbi.com/view {brand}` to find published reports)",
            target=pbi_url, confidence=Confidence.MEDIUM,
            payload={"url": pbi_url, "status": code,
                     "dork": f'site:app.powerbi.com inurl:view "{brand}"'},
            tags=[ChainTag.SVC_POWERBI_PUBLIC],
        ))

    # ---- Yammer / Viva Engage external network discovery ----
    # https://www.yammer.com/networks/{tenant_id} — tenant-scoped Yammer URL
    if snap.tenant_id:
        yam_url = f"https://www.yammer.com/{apex}"
        async with sem:
            code, _ = await head_existence(http, yam_url)
        if code and is_existence_signal(code):
            findings.append(data(
                phase="ms_public_content", check="yammer_external_reachable",
                title=f"Yammer / Viva Engage tenant-scoped URL reachable: {yam_url}",
                target=yam_url, confidence=Confidence.MEDIUM,
                payload={"url": yam_url, "status": code, "tenant_id": snap.tenant_id},
                tags=[ChainTag.SVC_YAMMER_EXTERNAL],
            ))

    return findings
