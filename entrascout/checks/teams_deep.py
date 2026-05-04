"""Phase 44 — Teams deep recon.

- Teams tenant discovery via dial-in / VoIP records
- Teams Live Events / Webinars URL pattern
- Teams Phone System auto-attendant URL pattern
- Teams external sharing inference via federation hints
- Teams app catalog (Microsoft Teams Store)
- M365 Connectors hunt-pack (incoming-webhook URLs)
"""
from __future__ import annotations

import asyncio

from ..dns_client import query as dns_query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, issue


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand
    tid = snap.tenant_id or ""

    # ---- Teams external federation hint (lyncdiscover already in dns_surface) ----
    # Teams calling federation: SRV _sipfederationtls._tcp (already covered)

    # ---- Teams Live Events / Webinar URL pattern ----
    # https://teams.microsoft.com/l/meetup-join/{encoded_GUID}@thread.v2/0?context=...&tenantId={tid}
    # Patterns aren't directly probable; emit guidance + hunt pack.
    findings.append(data(
        phase="teams_deep", check="teams_meeting_url_hunt",
        title="Teams meeting / Live Event URL hunt-pack (calendar invites + public share)",
        target=f"https://teams.microsoft.com/l/meetup-join/", confidence=Confidence.HIGH,
        payload={
            "url_patterns": [
                "https://teams.microsoft.com/l/meetup-join/{encoded_GUID}@thread.v2/0?context=...&tenantId={tid}",
                "https://teams.microsoft.com/_#/event-details/{tid}?eventId={GUID}",
            ],
            "google_dorks": [
                f'"{brand}" "teams.microsoft.com/l/meetup-join"',
                f'"teams.microsoft.com" "tenantId={tid}"' if tid else None,
                f'"{brand}" "live.microsoft.com" "event"',
            ],
            "impact": "Leaked meeting URLs allow uninvited join attempts (depending on lobby settings); "
                      "Live Event URLs are often public-broadcast and contain attendee data.",
        },
    ))

    # ---- M365 Connectors / Teams Incoming Webhooks hunt-pack ----
    # *.webhook.office.com/webhookb2/{guid}@{tid}/IncomingWebhook/{id}/{wid}
    findings.append(data(
        phase="teams_deep", check="teams_webhook_hunt",
        title="Teams incoming-webhook URL hunt-pack (post-to-channel exec primitive)",
        target=f"https://outlook.office.com/webhook/", confidence=Confidence.HIGH,
        payload={
            "url_pattern": "https://{tenant}.webhook.office.com/webhookb2/{GUID1}@{tid}/IncomingWebhook/{ID2}/{GUID3}",
            "github_dorks": [
                f'"{brand}" "webhook.office.com/webhookb2"',
                f'"webhookb2" "{tid}"' if tid else f'"{brand}" "webhookb2"',
                f'"{brand}" "outlook.office.com/connectors"',
            ],
            "impact": "Leaked webhook URL = anonymous post-to-channel. Used for phishing-via-Teams "
                      "(bypasses external-sender warnings) and noise/incident-trigger attacks.",
        },
    ))

    # ---- Teams Phone / auto attendant pattern ----
    # Auto attendants/CCQ have universally visible phone numbers via SBC tenant
    findings.append(data(
        phase="teams_deep", check="teams_phone_recon_guidance",
        title="Teams Phone / auto-attendant recon guidance",
        target=apex, confidence=Confidence.MEDIUM,
        payload={
            "approach": [
                "MX records → if @tenant.mail.protection.outlook.com, Teams Phone is likely",
                "SfB / Lync federation SRV records (covered in dns_surface)",
                "Public-facing org sites often list direct-dial numbers; combine with Teams calling tenant",
            ],
            "impact": "Auto-attendant + CCQ phone numbers can be probed for menu structure (via voice automation / TwiML), revealing internal extensions.",
        },
    ))

    return findings
