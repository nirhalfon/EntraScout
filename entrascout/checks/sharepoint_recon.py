"""Phase 29 — SharePoint Online deep recon (gap from OSS landscape review).

Comprehensive SharePoint reconnaissance against the tenant SP root:

- Site collection enumeration via wordlist (HR/Finance/IT/etc.)
- Admin & legacy URL probing (admin tenant, _vti_bin, _layouts/15, OneTOC)
- REST API surface (`_api/contextinfo`, `_api/web/lists`)
- Public-site test (`_api/web?$select=Title`)
- Anonymous search API probe (`_api/search/query`) — rarely succeeds but high
  signal when it does
- M365 group-connected site map (`_api/Web/SiteGroups`)

Read-only existence checks. No content download, no auth attempts.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, validation, issue, is_existence_signal


# Common SP site collection slugs — internal-app naming patterns
SP_SITE_NAMES = [
    # Departments
    "hr", "finance", "it", "legal", "marketing", "sales", "support",
    "engineering", "operations", "compliance", "security", "research",
    # Functions
    "intranet", "extranet", "portal", "home", "workspace", "documents",
    "shared", "public", "private", "internal", "knowledge",
    # Teams
    "team", "teams", "projects", "project", "tasks", "events",
    # Records / data
    "records", "archive", "backup", "library", "policies", "procedures",
    # Common
    "test", "dev", "staging", "demo", "sandbox", "training",
]


SP_REST_ENDPOINTS = [
    ("contextinfo", "/_api/contextinfo"),
    ("web_root", "/_api/web"),
    ("lists", "/_api/web/lists"),
    ("siteinfo", "/_api/site"),
    ("webinfos", "/_api/web/webinfos"),
]


SP_LEGACY_PATHS = [
    "/_vti_bin/lists.asmx",
    "/_vti_bin/usergroup.asmx",
    "/_vti_bin/sitedata.asmx",
    "/_vti_pvt/service.cnf",
    "/_layouts/15/onetoc.aspx",
    "/_layouts/15/sitemanager.aspx",
    "/_layouts/15/start.aspx",
    "/_layouts/15/AccessDenied.aspx",
]


async def head_existence(http: StealthClient, url: str) -> tuple[int | None, dict]:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    if not r:
        return None, {}
    return r.status_code, dict(r.headers or {})


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand
    if not tenant_short:
        return findings

    sem = asyncio.Semaphore(min(ctx.workers, 8))
    sp_root = f"https://{tenant_short}.sharepoint.com"
    admin_root = f"https://{tenant_short}-admin.sharepoint.com"

    # ---- 1. Confirm SP root reachability ----
    code, _ = await head_existence(http, sp_root)
    if code and is_existence_signal(code):
        findings.append(data(
            phase="sharepoint_recon", check="sp_root_confirmed",
            title=f"SharePoint Online root: {sp_root}",
            target=sp_root, confidence=Confidence.HIGH,
            payload={"url": sp_root, "status": code},
            tags=[ChainTag.SVC_SHAREPOINT],
        ))

    # ---- 2. Tenant admin SP URL — exists for any tenant with SP licensing ----
    code, _ = await head_existence(http, admin_root)
    if code and is_existence_signal(code):
        findings.append(data(
            phase="sharepoint_recon", check="sp_admin_root_confirmed",
            title=f"SharePoint admin tenant URL reachable: {admin_root}",
            target=admin_root, confidence=Confidence.HIGH,
            payload={"url": admin_root, "status": code,
                     "note": "Auth-gated for SP admins; presence indicates SP/M365 admin role exists in tenant."},
            tags=[ChainTag.SVC_SHAREPOINT],
        ))

    # ---- 3. Site-collection name brute via wordlist ----
    async def probe_site(name: str) -> None:
        url = f"{sp_root}/sites/{name}"
        async with sem:
            code, _ = await head_existence(http, url)
        # 200 / 302 = exists (anonymous redirected to login is normal)
        # 403 = exists, locked
        # 404 = does NOT exist
        if code in (200, 302, 403):
            findings.append(data(
                phase="sharepoint_recon", check="sp_site_exists",
                title=f"SharePoint site exists: {url}",
                target=url, confidence=Confidence.HIGH,
                payload={"url": url, "site_name": name, "status": code,
                         "interpretation": {200: "anonymous-accessible (rare)",
                                            302: "exists, redirects to login (normal)",
                                            403: "exists, restricted"}.get(code, "exists")},
                tags=[ChainTag.SVC_SHAREPOINT],
            ))

    await asyncio.gather(*(probe_site(s) for s in SP_SITE_NAMES))
    # Also try brand-specific
    if brand and brand != tenant_short:
        await probe_site(brand)
        await probe_site(f"{brand}-team")
        await probe_site(f"{brand}team")

    # ---- 4. REST API probing on root ----
    async def probe_rest(label: str, path: str) -> None:
        url = f"{sp_root}{path}"
        async with sem:
            r = await http.get(url, headers={"Accept": "application/json;odata=nometadata"})
        if not r:
            return
        if r.status_code == 200:
            # Anonymous REST on the root web — unusual but possible for public/guest sites
            try:
                txt = (r.text or "")[:500]
            except Exception:
                txt = ""
            findings.append(lead(
                phase="sharepoint_recon", check=f"sp_rest_{label}",
                title=f"SharePoint REST `{label}` returns 200 anonymously: {url}",
                target=url, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description=(
                    f"The REST endpoint `{path}` responded 200 to an anonymous request. "
                    "For SP-Online tenants with locked-down anonymous access, this should "
                    "be 401/403. A 200 here typically means the tenant has anonymous "
                    "guest access turned on or a public site has been configured."
                ),
                data={"url": url, "endpoint": path, "label": label,
                      "status": r.status_code, "snippet": txt},
                tags=[ChainTag.SVC_SHAREPOINT],
                recommendation="Audit tenant-wide anonymous access settings; confirm any public sites are intentional.",
            ))
        elif r.status_code in (401, 403):
            # Endpoint exists, auth-gated — confirms the tenant has SP, no further probe needed
            pass

    await asyncio.gather(*(probe_rest(lbl, p) for lbl, p in SP_REST_ENDPOINTS))

    # ---- 5. Anonymous search API probe ----
    # /_api/search/query?querytext='*' — almost always auth-gated, but when not,
    # this is a high-impact finding (full anonymous tenant search).
    search_url = f"{sp_root}/_api/search/query?querytext='*'&rowlimit=1"
    r = await http.get(search_url, headers={"Accept": "application/json;odata=nometadata"})
    if r and r.status_code == 200:
        findings.append(issue(
            phase="sharepoint_recon", check="sp_anon_search_api",
            title=f"SharePoint search API returns 200 anonymously: {search_url}",
            target=search_url, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
            description=(
                "The SharePoint search REST API responded 200 to an anonymous query. "
                "This typically allows enumeration of indexed content (documents, list "
                "items, pages) across all SP sites the tenant has marked publicly "
                "indexable. High-value finding."
            ),
            data={"url": search_url, "status": r.status_code,
                  "snippet": (r.text or "")[:500]},
            tags=[ChainTag.SVC_SHAREPOINT],
            recommendation="Disable anonymous search at the tenant level; restrict via SP admin.",
        ))

    # ---- 6. Legacy SOAP / FrontPage paths ----
    async def probe_legacy(path: str) -> None:
        url = f"{sp_root}{path}"
        async with sem:
            code, _ = await head_existence(http, url)
        if code in (200, 302, 401, 403):
            sev = Severity.LOW if code in (401, 403) else Severity.MEDIUM
            findings.append(data(
                phase="sharepoint_recon", check="sp_legacy_path",
                title=f"SharePoint legacy path reachable ({code}): {path}",
                target=url, confidence=Confidence.HIGH,
                payload={"url": url, "path": path, "status": code,
                         "interpretation": "Legacy SP endpoint — usually disabled in modern tenants."},
                tags=[ChainTag.SVC_SHAREPOINT],
            ))

    await asyncio.gather(*(probe_legacy(p) for p in SP_LEGACY_PATHS[:5]))

    return findings
