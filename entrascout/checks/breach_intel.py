"""Phase 47 — Breach / leak indicator (HaveIBeenPwned + emit dorks for paste sites).

Without an HIBP API key, can't query the breached-account API. Without a
key, we emit:
- Dork pack for pastebin / ghostbin / hastebin / paste.lol / 0bin etc.
- Dork pack for HIBP itself

With `HIBP_API_KEY` env var, query the breached-domain API for the org.
"""
from __future__ import annotations

import os

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]

    # ---- Hunt-pack output ----
    findings.append(data(
        phase="breach_intel", check="breach_dork_pack",
        title=f"Breach / leak hunt-pack for {apex}",
        target=apex, confidence=Confidence.HIGH,
        payload={
            "search_engines": [
                f'site:haveibeenpwned.com "{apex}"',
                f'site:pastebin.com "{apex}"',
                f'site:paste.lol "{apex}"',
                f'site:ghostbin.com "{apex}"',
                f'site:0bin.net "{apex}"',
                f'site:hastebin.com "{apex}"',
            ],
            "github_dorks": [
                f'"{apex}" "password"',
                f'"{apex}" "secret"',
                f'"{apex}" "api_key"',
                f'"@{apex}" filename:.env',
                f'"@{apex}" filename:credentials',
            ],
            "tooling": {
                "h8mail": "h8mail -t @{apex} (mail breach)".format(apex=apex),
                "hibp_api": "Auth required — set HIBP_API_KEY env var to enable inline queries",
                "dehashed": "https://www.dehashed.com/search?query={}".format(apex),
            },
        },
    ))

    # ---- HIBP breached-domain query (if key available) ----
    hibp_key = os.environ.get("HIBP_API_KEY", "").strip()
    if hibp_key:
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={apex}"
        r = await http.get(url, headers={"hibp-api-key": hibp_key, "User-Agent": "EntraScout"})
        if r and r.status_code == 200:
            try:
                breaches = r.json() or []
            except Exception:
                breaches = []
            if breaches:
                findings.append(lead(
                    phase="breach_intel", check="hibp_breaches_known",
                    title=f"{len(breaches)} known breaches reference @{apex}",
                    target=url, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                    description=(
                        "HaveIBeenPwned reports breaches that exposed accounts at this domain. "
                        "Audit-relevant for credential-rotation cadence."
                    ),
                    data={"breach_count": len(breaches),
                          "breaches": [{"name": b.get("Name"), "date": b.get("BreachDate"),
                                        "count": b.get("PwnCount")} for b in breaches[:20]]},
                ))

    return findings
