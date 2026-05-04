"""Phase 18 — GitHub code-search dork pack (gap #2).

Generates a curated dork pack for GitHub Code Search and (optionally) executes
queries when GITHUB_TOKEN is provided in the environment. Dorks target leaked
tenant IDs, storage account names, connection strings, and customer app IDs.

Without a token: emits the dork pack as a `recommendation` artifact users can
paste into github.com/search.

With a token: executes via `https://api.github.com/search/code` and reports
hit counts (not file contents — that requires further read).
"""
from __future__ import annotations

import os

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


def build_dorks(brand: str, tenant_id: str | None, tenant_default_name: str | None) -> list[dict]:
    dorks: list[dict] = []
    if tenant_id:
        dorks.append({
            "category": "tenant-id",
            "query": f'"{tenant_id}"',
            "why": "Direct tenant ID leak in any config file",
        })
        dorks.append({
            "category": "tenant-id-yaml",
            "query": f'tenantId: "{tenant_id}"',
            "why": "Tenant ID hardcoded in YAML (CI/CD configs)",
        })
        dorks.append({
            "category": "tenant-id-json",
            "query": f'"tenantId": "{tenant_id}"',
            "why": "Tenant ID hardcoded in JSON (appsettings.json, etc.)",
        })
    if tenant_default_name:
        short = tenant_default_name.replace(".onmicrosoft.com", "")
        dorks.append({
            "category": "tenant-domain",
            "query": f'"{short}.onmicrosoft.com"',
            "why": "Tenant default domain referenced in code",
        })
    if brand:
        dorks.extend([
            {"category": "storage-key",
             "query": f'"DefaultEndpointsProtocol=https" "AccountName={brand}"',
             "why": "Connection string with brand-prefixed Storage AccountName"},
            {"category": "storage-blob",
             "query": f'"{brand}" "blob.core.windows.net"',
             "why": "Brand reference + Azure Blob hostname"},
            {"category": "key-vault-url",
             "query": f'"{brand}" ".vault.azure.net"',
             "why": "Brand reference + Key Vault FQDN"},
            {"category": "logic-app-trigger",
             "query": f'"{brand}" "logic.azure.com" "/triggers/manual/paths/invoke"',
             "why": "Logic App trigger SAS URL leak (REMOTE EXEC)",
             "severity_hint": "high",
             },
            {"category": "service-bus",
             "query": f'"Endpoint=sb://" "{brand}"',
             "why": "Service Bus connection string with SAS"},
            {"category": "appsettings",
             "query": f'"{brand}" filename:appsettings.json',
             "why": ".NET appsettings.json with brand reference (often has secrets)"},
            {"category": "env-azure",
             "query": f'"{brand}" "AZURE_CLIENT_SECRET"',
             "why": "Azure SP secret env var leaks"},
            {"category": "azurefd-cdn",
             "query": f'"{brand}" ".azurefd.net"',
             "why": "Azure Front Door endpoints"},
        ])
    return dorks


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]

    dorks = build_dorks(brand, snap.tenant_id, snap.tenant_default_name)
    if not dorks:
        return findings

    # Without GITHUB_TOKEN we just emit the dork pack as a manual artifact.
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    findings.append(data(
        phase="github_dorks", check="github_dork_pack",
        title=f"GitHub code-search dork pack ({len(dorks)} queries)",
        target="https://github.com/search?type=code", confidence=Confidence.HIGH,
        payload={"dorks": dorks, "count": len(dorks),
                 "manual_search_url": "https://github.com/search?type=code&q={QUERY}",
                 "github_token_present": bool(token)},
        tags=[ChainTag.GITHUB_LEAK],
    ))

    if not token:
        return findings

    # With token: execute search queries via REST API. Rate-limited (10 req/min unauth, 30/min auth).
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.text-match+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    for d in dorks:
        url = f"https://api.github.com/search/code?q={d['query']}"
        r = await http.get(url, headers=headers)
        if not r or r.status_code != 200:
            continue
        try:
            j = r.json()
        except Exception:
            continue
        total = j.get("total_count", 0)
        if total > 0:
            sample_repos = list({(it.get("repository") or {}).get("full_name", "") for it in (j.get("items") or [])[:5]})
            sev = Severity.HIGH if d.get("severity_hint") == "high" else Severity.MEDIUM
            findings.append(lead(
                phase="github_dorks", check=f"github_dork_hit_{d['category'].replace('-','_')}",
                title=f"GitHub leak hit ({d['category']}, {total} results): {d['query']}",
                target=f"https://github.com/search?type=code&q={d['query']}",
                severity=sev, confidence=Confidence.HIGH,
                description=f"GitHub Code Search returned {total} results for the query. Sample repos: {', '.join(sample_repos[:5])}",
                data={**d, "total": total, "sample_repos": sample_repos},
                tags=[ChainTag.GITHUB_LEAK],
                recommendation="Investigate matching repos for committed secrets / credentials. If they belong to your org, rotate immediately.",
            ))

    return findings
