"""Phase 10 — Bing-dork URL generation + optional API search."""
from __future__ import annotations

from urllib.parse import quote_plus

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


def _dorks(tenant_short: str | None, brand: str) -> list[tuple[str, str, str]]:
    """Return list of (label, query, severity_hint)."""
    items: list[tuple[str, str, str]] = []
    if tenant_short:
        items += [
            ("SharePoint indexed pages", f"site:{tenant_short}.sharepoint.com", "MEDIUM"),
            ("OneDrive indexed content", f"site:{tenant_short}-my.sharepoint.com", "HIGH"),
            ("Power BI publish-to-web", f"site:app.powerbi.com/view {brand}", "HIGH"),
            ("Public Forms", f"site:forms.office.com {brand}", "MEDIUM"),
            ("Sway docs", f"site:sway.office.com {brand}", "MEDIUM"),
            ("Power Pages portals", f"site:powerappsportals.com {brand}", "HIGH"),
            ("Power Pages OData (Dataverse leak)", f"site:powerappsportals.com inurl:_odata", "HIGH"),
            ("Azure DevOps public projects", f"site:dev.azure.com {brand}", "MEDIUM"),
            ("Legacy Azure DevOps", f"site:visualstudio.com {brand}", "LOW"),
            ("Azure App Service hosts", f"site:azurewebsites.net {brand}", "MEDIUM"),
            ("Public blob URLs", f"site:blob.core.windows.net {brand}", "HIGH"),
            ("Custom Copilot Studio bots", f"\"copilot studio\" {brand}", "HIGH"),
            ("Indexed Teams meetings", f"site:teams.microsoft.com/l/meetup-join \"{brand}\"", "LOW"),
            ("M365 Bookings pages", f"site:outlook.office.com bookings {brand}", "MEDIUM"),
        ]
    return items


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand

    items = _dorks(tenant_short, brand)
    if not items:
        return findings

    # Always emit dork URLs, even without API key
    dork_lines = ["# Bing-dork pack — paste into Bing or feed to API", ""]
    for label, q, sev in items:
        dork_lines.append(f"- [{label}](https://www.bing.com/search?q={quote_plus(q)})  ·  `{q}`  ·  *{sev}*")
    om.save_raw("bing_dorks/queries.md", "\n".join(dork_lines))

    findings.append(data(
        phase="bing_dorks", check="dork_pack_generated",
        title=f"Generated {len(items)} Bing-dork queries",
        target=ctx.target, confidence=Confidence.HIGH,
        payload={"count": len(items), "queries": [{"label": l, "q": q, "severity_hint": s} for l, q, s in items],
                 "raw_path": "raw/bing_dorks/queries.md"},
    ))

    if not ctx.bing_api_key:
        findings.append(lead(
            phase="bing_dorks", check="dork_pack_manual",
            title="Run the Bing dork pack manually (or supply --bing-key for automated harvest)",
            target=ctx.target, severity=Severity.LOW, confidence=Confidence.MEDIUM,
            description="Bing API key not provided. Open the queries in `raw/bing_dorks/queries.md` to harvest indexed content from outside the tenant.",
            recommendation="Pay close attention to the OneDrive, Power Pages OData, and Power BI publish-to-web dorks — these often surface real data leaks.",
        ))
        return findings

    # ---- Bing Web Search API ----
    api_url = "https://api.bing.microsoft.com/v7.0/search"
    headers = {"Ocp-Apim-Subscription-Key": ctx.bing_api_key}
    for label, q, sev in items:
        r = await http.get(api_url, headers=headers, params={"q": q, "count": 20, "safeSearch": "Off"})
        if not r or r.status_code >= 400:
            continue
        try:
            j = r.json()
        except Exception:  # noqa: BLE001
            continue
        web = j.get("webPages", {}).get("value", [])
        if not web:
            continue
        om.save_raw(f"bing_dorks/results_{label.replace(' ', '_')}.json", str(j))
        urls = [w.get("url") for w in web if w.get("url")]
        sev_enum = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}.get(sev, Severity.LOW)
        findings.append(lead(
            phase="bing_dorks", check=f"hit_{label.replace(' ', '_').lower()}",
            title=f"Bing dork hit ({label}): {len(urls)} results",
            target=ctx.target, severity=sev_enum, confidence=Confidence.MEDIUM,
            description=f"Indexed content surfaced for query `{q}`.",
            data={"query": q, "results": urls[:50]},
            recommendation="Review each URL for data exposure. Removing content from the index requires both removing the page AND requesting Bing Webmaster Tools removal.",
        ))

    return findings
