"""Phase 33 — Dark corners of Microsoft / Azure / M365.

Niche / forgotten / preview Microsoft surfaces that organizations frequently
leave open or misconfigured. Each is an existence-check on a tenant-scoped
URL pattern. Findings here are signals — actual misconfig requires follow-up.

Surfaces probed:
- Microsoft Sway (`sway.cloud.microsoft.com`, `sway.office.com/{ID}`)
- Microsoft Visio for Web (`visio.office.com`)
- Microsoft Project for the Web
- Microsoft Planner (`tasks.office.com`, `planner.cloud.microsoft.com`)
- Microsoft To Do
- Microsoft Whiteboard (`whiteboard.office.com`)
- Microsoft Bookings With Me (`outlook.office.com/bookwithme/{user}`)
- Microsoft Customer Voice / Forms Pro (`customervoice.microsoft.com`)
- Microsoft Power Apps public embed (`apps.powerapps.com/play/{appId}`)
- Microsoft Defender for Identity (`*.atp.azure.com`)
- Microsoft Defender for Office (`protection.outlook.com`)
- Microsoft Purview (`purview.microsoft.com`)
- Microsoft Viva (`viva.engage.microsoft.com`, `viva.connections`)
- Microsoft 365 Lighthouse (`lighthouse.microsoft.com` — MSPs)
- Microsoft Entra Verified ID
- Microsoft Entra Permissions Management (CloudKnox legacy: `*.cloudknox.io`)
- Microsoft Entra External ID (newer than B2C)
- Microsoft Forms Customer Voice questionnaires
- Power Pages Maker portal (`make.powerapps.com`)
- Microsoft Graph Toolkit demo apps
- Microsoft Bing for Business
- Microsoft Editor / Editor Premium
- Microsoft Search admin (`bing.com/business/...`)
- Microsoft Lists (`lists.live.com`)
- Microsoft Roadmap mentions
- Power Platform Build Tools telemetry
- Office 365 Burn-In suite legacy
- Microsoft Stream Live
- Microsoft Loop App (`loop.microsoft.com/p/...`)
- Microsoft Teams Live Events
- Microsoft Bookings Classic (`bookings.office.com`)
- Microsoft Forms classic
- Microsoft 365 admin deep-link (`admin.microsoft.com/?tenantId=...`)
- Defender XDR portal deep-link
- Azure portal deep-link
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, is_existence_signal


# (label, url_template, severity, why) — url_template uses {brand}, {tenant}, {tid}
DARK_CORNERS = [
    # Sway
    ("Microsoft Sway public docs",
     "https://sway.cloud.microsoft.com/{tenant}",
     Severity.LOW,
     "Sway public docs are anonymous-shareable; tenant-scoped Sway exposes shareable presentations."),
    # Visio for Web
    ("Microsoft Visio for the Web",
     "https://visio.office.com",
     Severity.LOW,
     "Universal — service existence only."),
    # Planner
    ("Microsoft Planner web",
     "https://tasks.office.com",
     Severity.LOW,
     "Planner web app — tenant authentication required for actual content."),
    # To Do
    ("Microsoft To Do",
     "https://to-do.office.com",
     Severity.LOW,
     "Universal. Auth required."),
    # Whiteboard
    ("Microsoft Whiteboard",
     "https://whiteboard.office.com",
     Severity.LOW,
     "Universal. Tenant-scoped boards may have public-link sharing."),
    # Bookings With Me
    ("Microsoft Bookings With Me (per-user)",
     "https://outlook.office.com/bookwithme/{tenant}",
     Severity.MEDIUM,
     "Bookings With Me lets individual users publish a personal scheduling page, separate from the org's Bookings Pages. "
     "Each page leaks the user's name, email, photo, and calendar availability — useful free PII for spear-phish."),
    # Customer Voice
    ("Microsoft Customer Voice (Forms Pro)",
     "https://customervoice.microsoft.com/Pages/projects.aspx",
     Severity.LOW,
     "Customer Voice publishes anonymous-completable surveys. Search Bing for `site:customervoice.microsoft.com {brand}`."),
    # Power Apps public play
    ("Microsoft Power Apps public play / embed",
     "https://apps.powerapps.com/play/e/default-{tid}",
     Severity.MEDIUM,
     "Power Apps can be configured for anonymous play (when the maker selects 'Allow guests' or shares a public play URL). "
     "Probe the tenant-default URL pattern; auth-gated apps return 302 to login."),
    # Defender for Identity (formerly Azure ATP)
    ("Microsoft Defender for Identity (Azure ATP) instance",
     "https://{tenant}.atp.azure.com",
     Severity.LOW,
     "Defender for Identity / Azure ATP customer instance URL. Existence indicates the org has Defender for Identity licensed."),
    # Microsoft 365 Defender (XDR)
    ("Microsoft 365 Defender (XDR) portal",
     "https://security.microsoft.com/?tid={tid}",
     Severity.LOW,
     "Auth-gated tenant-deep-link to the XDR portal."),
    # Microsoft Purview
    ("Microsoft Purview compliance portal",
     "https://compliance.microsoft.com/?tid={tid}",
     Severity.LOW,
     "Auth-gated tenant-deep-link to compliance portal."),
    # Microsoft Entra admin center (replaces Azure AD admin)
    ("Microsoft Entra admin center deep-link",
     "https://entra.microsoft.com/?tenantId={tid}",
     Severity.LOW,
     "Auth-gated tenant-deep-link."),
    # M365 admin center
    ("Microsoft 365 admin center deep-link",
     "https://admin.microsoft.com/?tenantId={tid}",
     Severity.LOW,
     "Auth-gated tenant-deep-link."),
    # Azure portal
    ("Azure portal tenant deep-link",
     "https://portal.azure.com/{tid}",
     Severity.LOW,
     "Auth-gated tenant-deep-link to Azure portal."),
    # Microsoft 365 Lighthouse (MSP-only)
    ("Microsoft 365 Lighthouse (MSP)",
     "https://lighthouse.microsoft.com",
     Severity.LOW,
     "Lighthouse is for MSPs managing customer tenants. Existence is universal; tenant being CSP-managed is the interesting signal (auth required to confirm)."),
    # Microsoft Loop public pages
    ("Microsoft Loop public workspaces",
     "https://loop.microsoft.com",
     Severity.LOW,
     "Universal endpoint. Bing-dork: `site:loop.microsoft.com {brand}`."),
    # Microsoft Forms (also classic)
    ("Microsoft Forms tenant-scoped landing",
     "https://forms.office.com/Pages/landing.aspx?tid={tid}",
     Severity.LOW,
     "Forms tenant-scoped page. Org may publish anonymous forms via /r/{ID} URLs."),
    # Power Platform Maker
    ("Power Apps maker portal (universal)",
     "https://make.powerapps.com",
     Severity.LOW,
     "Universal. Use `?tenantId={tid}` to deep-link."),
    # Microsoft Editor
    ("Microsoft Editor (Word grammar)",
     "https://editor.microsoft.com",
     Severity.LOW,
     "Universal Editor endpoint. Tenant-private settings are stored in the user profile — auth required to enumerate."),
    # Bing for Business / Microsoft Search
    ("Microsoft Search (Bing for Business) admin",
     "https://bing.com/business/explore?tid={tid}",
     Severity.LOW,
     "Auth-gated tenant-deep-link."),
    # Microsoft Lists (consumer)
    ("Microsoft Lists (consumer / lists.live.com)",
     "https://lists.live.com",
     Severity.LOW,
     "Consumer Lists — separate from SP Lists. Org may have content here if employees mix accounts."),
    # Power Automate dashboard
    ("Power Automate dashboard",
     "https://make.powerautomate.com",
     Severity.LOW,
     "Universal."),
    # Defender for Office (mail flow)
    ("Defender for Office 365 (Exchange Online Protection) admin",
     "https://protection.outlook.com",
     Severity.LOW,
     "EOP / Defender for Office admin URL. Auth required."),
    # Stream Live
    ("Microsoft Stream Live (current-gen Stream)",
     "https://www.microsoft.com/en-us/microsoft-365/stream",
     Severity.LOW,
     "Marketing landing. Tenant-scoped Stream content is on SharePoint."),
    # Teams Live Events
    ("Microsoft Teams Live Events",
     "https://teams.microsoft.com/_#/event-details/{tid}",
     Severity.LOW,
     "Teams meeting / live event URLs are guessable when GUIDs are leaked in calendar invites."),
    # Microsoft 365 / Roadmap mentions
    ("Microsoft 365 roadmap mention search",
     "https://www.microsoft.com/microsoft-365/roadmap?searchterms={brand}",
     Severity.LOW,
     "Search for tenant brand mentions in MS 365 roadmap. Sometimes leaks tenant participation in previews."),
    # Power Pages maker
    ("Power Pages maker portal",
     "https://make.powerpages.microsoft.com",
     Severity.LOW,
     "Universal."),
    # Bookings (classic, separate from Bookings With Me)
    ("Microsoft Bookings classic landing",
     "https://outlook.office.com/owa/?path=/mybookings",
     Severity.LOW,
     "Auth-gated."),
    # Defender for Identity sensor URL
    ("Defender for Identity sensor URL pattern",
     "https://{tenant}sensorapi.atp.azure.com",
     Severity.LOW,
     "Sensor API endpoint pattern. Existence indicates active Defender for Identity deployment."),
    # Cloudknox (legacy Microsoft Entra Permissions Management)
    ("Microsoft Entra Permissions Management (legacy CloudKnox)",
     "https://app.cloudknox.io",
     Severity.LOW,
     "Universal. Tenant onboarding requires invite."),
]


async def probe_url(http: StealthClient, url: str) -> int | None:
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

    async def probe(label: str, tpl: str, severity: Severity, why: str) -> None:
        url = (tpl
               .replace("{brand}", brand)
               .replace("{tenant}", tenant_short)
               .replace("{tid}", tid))
        async with sem:
            code = await probe_url(http, url)
        if code and is_existence_signal(code):
            findings.append(data(
                phase="dark_corners", check="dark_corner_surface",
                title=f"Microsoft surface reachable: {label}",
                target=url, confidence=Confidence.MEDIUM,
                payload={"label": label, "url": url, "status": code, "why": why,
                         "severity_hint": severity.value if hasattr(severity, "value") else str(severity)},
            ))

    await asyncio.gather(*(probe(lbl, tpl, sev, why) for lbl, tpl, sev, why in DARK_CORNERS))

    return findings
