"""Phase 49 — Azure Subscription ID leak hunt.

Subscription IDs (GUIDs) leak in:
- ARM templates committed to public repos
- App settings / appsettings.json
- HTML comments on App Service deployments
- Power BI report metadata
- Stack Overflow answers / Postman collections

Confirmed subscription ID + tenant ID = recon goldmine for any post-auth pivot.
"""
from __future__ import annotations

import re

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


GUID_PATTERN = r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]

    # ---- Hunt-pack ----
    findings.append(data(
        phase="subscription_leak", check="azure_subscription_hunt_pack",
        title=f"Azure subscription ID leak hunt-pack ({brand} / {apex})",
        target=apex, confidence=Confidence.HIGH,
        payload={
            "github_dorks": [
                f'"{brand}" "subscriptions/" "/resourceGroups/" extension:json',
                f'"{brand}" "subscriptionId" filename:azure-pipelines.yml',
                f'"{brand}" "/.management.azure.com/subscriptions/"',
                f'"{brand}" "subscription-id"',
                f'"{brand}" "/subscriptions/" "Microsoft."',  # ARM resource paths
            ],
            "scrape_targets": {
                "stack_overflow": f'site:stackoverflow.com "{brand}" "subscription"',
                "postman": f'site:postman.com "{brand}" "subscriptions/"',
                "github_gists": f'site:gist.github.com "{brand}" "subscriptions/"',
            },
            "impact": [
                "Confirmed sub_id + tenant_id = pre-flight for any token-based pivot.",
                "Combined with leaked SP credentials (separate vector) = full Azure subscription enum.",
                "Combined with Resource Manager API + reader role = read entire infra.",
            ],
        },
    ))

    # ---- Inspect HTML comments / response bodies of detected App Services for sub-ID leaks ----
    candidate_urls: list[str] = []
    for f in om.findings:
        target = (f.target or "")
        if ".azurewebsites.net" in target and target.startswith("https://"):
            candidate_urls.append(target.split("?")[0])
    candidate_urls = list(set(candidate_urls))[:10]

    seen_subs: set[str] = set()
    for url in candidate_urls:
        try:
            r = await http.get(url)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
        except Exception:
            continue
        for m in re.finditer(GUID_PATTERN, body):
            guid = m.group(0).lower()
            # Skip the tenant ID itself
            if guid == (snap.tenant_id or "").lower():
                continue
            if guid not in seen_subs:
                seen_subs.add(guid)

    if seen_subs:
        findings.append(lead(
            phase="subscription_leak", check="guid_leak_in_appservice_body",
            title=f"GUIDs leaked in App Service response bodies ({len(seen_subs)} unique)",
            target=apex, severity=Severity.LOW, confidence=Confidence.MEDIUM,
            description=(
                "GUIDs found in HTML/JS responses from detected App Services. May include "
                "Azure subscription IDs, resource IDs, application IDs, instrumentation keys, "
                "or unrelated GUIDs. Triage manually."
            ),
            data={"unique_guids": sorted(seen_subs)[:50],
                  "sources": candidate_urls,
                  "next": "Cross-reference each GUID with Azure subscription / tenant / app namespaces."},
        ))

    return findings
