"""Phase 13 — Azure tenant-bound resources (DNS-based existence + selected unauth probes)."""
from __future__ import annotations

import asyncio
from typing import Any

from ..dns_client import query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, is_existence_signal, issue, lead, validation
from . import blob_deep


# Many Azure suffixes return DNS for ANY label (wildcard), so DNS alone is not proof.
# We always HTTP-probe these and require a status code that proves a service backend.
# (suffix, label, chain_tag, dns_is_definitive, validating_status_codes)
# - dns_is_definitive: True means DNS resolution IS proof (Storage / SB / Cosmos all return NXDOMAIN
#   for non-existent accounts). False means we MUST HTTP-probe and see a real backend status.
AZURE_HOST_PATTERNS: list[tuple[str, str, ChainTag, bool, set[int]]] = [
    ("azurewebsites.net", "App Service", ChainTag.AZ_APPSERVICE, False, {200, 301, 302, 401, 403, 404, 503}),
    ("scm.azurewebsites.net", "Kudu (App Service deployment)", ChainTag.AZ_KUDU_EXPOSED, False, {200, 401, 403}),
    ("azurestaticapps.net", "Static Web App", ChainTag.AZ_STATIC_WEBAPP, False, {200, 301, 302, 401, 403}),
    ("azurecr.io", "Container Registry", ChainTag.AZ_CONTAINER_REGISTRY, False, {200, 401}),
    ("azurefd.net", "Front Door", ChainTag.AZ_FRONT_DOOR, False, {200, 301, 302, 401, 403}),
    ("azureedge.net", "CDN", ChainTag.AZ_CDN, False, {200, 301, 302, 401, 403}),
    ("blob.core.windows.net", "Blob Storage", ChainTag.AZ_BLOB, True, set()),
    ("file.core.windows.net", "File Storage", ChainTag.AZ_FILE, True, set()),
    ("queue.core.windows.net", "Queue Storage", ChainTag.AZ_QUEUE, True, set()),
    ("table.core.windows.net", "Table Storage", ChainTag.AZ_TABLE, True, set()),
    ("servicebus.windows.net", "Service Bus", ChainTag.AZ_SERVICEBUS, True, set()),
    ("azure-api.net", "API Management", ChainTag.AZ_APIM, False, {200, 301, 302, 401, 404}),
    ("documents.azure.com", "Cosmos DB", ChainTag.AZ_COSMOS, True, set()),
    ("search.windows.net", "Cognitive Search", ChainTag.AZ_SEARCH, True, set()),
]


def _candidate_names(snap: TenantSnapshot, ctx: RunContext) -> list[str]:
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    candidates: set[str] = {brand}
    if snap.tenant_default_name:
        candidates.add(snap.tenant_default_name.replace(".onmicrosoft.com", ""))
    # Common environment / role permutations
    envs = ("dev", "stg", "prod", "test", "qa", "uat", "internal", "external",
            "api", "app", "data", "web", "ops", "auth", "id", "ingest",
            "etl", "ml", "ai", "report", "files", "media", "static", "cdn", "log", "logs")
    for s in envs:
        candidates.add(f"{brand}{s}")
        candidates.add(f"{brand}-{s}")
        candidates.add(f"{s}{brand}")
        candidates.add(f"{s}-{brand}")
    return [c for c in candidates if c and c.replace("-", "").isalnum()]


async def probe_blob_listing(http: StealthClient, host: str) -> tuple[bool, int | None]:
    """Try anonymous container listing — `?comp=list&maxresults=5`. 200 = public listing."""
    url = f"https://{host}/?comp=list&maxresults=5"
    r = await http.get(url)
    if not r:
        return False, None
    return (r.status_code == 200 and "<EnumerationResults" in r.text), r.status_code


# Markers in response body that indicate AAD Easy Auth (App Service Authentication)
# is intercepting unauth requests. A 200 response with these markers = AUTH-PROTECTED,
# not a misconfigured open Kudu.
EASY_AUTH_MARKERS = (
    "Sign in to Microsoft online",
    "Microsoft.AspNetCore.Authentication",
    "AppServiceAuthentication",
    "/.auth/login/aad",
    "Redirecting...",
    "<title>Redirecting",
    "<title>Redi",
    "easyauth",
    "Copyright (C) Microsoft Corporation",  # Easy Auth login redirect HTML always has this
    "login.microsoftonline.com",
    "login.windows.net",
)

# Markers that indicate UNPROTECTED Kudu UI exposed
KUDU_UNAUTH_MARKERS = (
    "Kudu Services",
    "kudu-tools",
    "id=\"environment\"",
    "/api/zipdeploy",  # only present in real Kudu UI, not login pages
    "Site extensions",
    "Kudu (",  # version banner
)


async def classify_kudu_response(http: StealthClient, host: str) -> tuple[str, dict]:
    """Return ('UNAUTH'|'EASYAUTH'|'401'|'UNKNOWN', info_dict)."""
    r = await http.get(f"https://{host}/")
    if not r:
        return "UNKNOWN", {"error": "no response"}
    code = r.status_code
    body = r.text or ""
    info = {"status": code, "body_len": len(body), "server": r.headers.get("server", ""),
            "content_type": r.headers.get("content-type", "")}
    if code == 401:
        return "401", info
    if code == 200:
        body_lower = body.lower()
        if any(m.lower() in body_lower for m in KUDU_UNAUTH_MARKERS):
            return "UNAUTH", info
        if any(m.lower() in body_lower for m in EASY_AUTH_MARKERS):
            return "EASYAUTH", info
        # Title sniff
        if "<title>redirect" in body_lower or "microsoft online" in body_lower:
            return "EASYAUTH", info
        # Default: unknown 200 — still suspicious but not confirmed unauth
        return "UNKNOWN", info
    return f"HTTP-{code}", info


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    candidates = _candidate_names(snap, ctx)

    sem = asyncio.Semaphore(ctx.workers)

    async def check(name: str, suffix: str, label: str, tag: ChainTag,
                    dns_is_definitive: bool, validating_codes: set[int]) -> None:
        host = f"{name}.{suffix}"
        async with sem:
            dns_records = await query(host, "A")
            if not dns_records:
                dns_records = await query(host, "CNAME")
        if not dns_records:
            return

        rec_payload: dict[str, Any] = {
            "resource_type": label, "host": host, "name": name, "suffix": suffix,
            "dns": dns_records,
        }

        # If suffix has wildcard DNS (Front Door / Static Web Apps / azurewebsites.net),
        # DNS resolving is NOT proof. We require an HTTP backend response.
        confidence = Confidence.HIGH
        if not dns_is_definitive:
            r = await http.head(f"https://{host}")
            if not r:
                r = await http.get(f"https://{host}")
            if not r:
                # No HTTP backend → false positive on wildcard. Skip entirely.
                return
            rec_payload["status"] = r.status_code
            rec_payload["server"] = r.headers.get("server", "")
            if r.status_code not in validating_codes:
                # DNS resolved (wildcard) but no real backend behind it. Skip.
                return
        else:
            # DNS-definitive (storage / Cosmos / SB) — DNS hit IS the signal
            confidence = Confidence.CONFIRMED

        findings.append(data(
            phase="azure_resources", check=f"az_{suffix.replace('.', '_')}",
            title=f"{label} hit: {host}",
            target=host, confidence=confidence,
            payload=rec_payload,
            tags=[tag],
        ))

        # Special: Blob anonymous listing
        if "blob.core.windows.net" in suffix:
            public, code = await probe_blob_listing(http, host)
            if public:
                findings.append(issue(
                    phase="azure_resources", check="blob_public_listing",
                    title=f"Blob storage allows anonymous container listing: {host}",
                    target=f"https://{host}/?comp=list", severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description="Storage account permits anonymous container enumeration. Often reveals confidential data.",
                    data={"host": host, "status": code, "resource_type": "Blob Storage"},
                    tags=[ChainTag.AZ_BLOB_PUBLIC_LISTING],
                    recommendation="Set storage account `AllowBlobPublicAccess` to `false` and review container-level public access settings.",
                ))

        # Special: Kudu (scm.azurewebsites.net) — classify auth posture
        if "scm.azurewebsites.net" in suffix:
            verdict, info = await classify_kudu_response(http, host)
            if verdict == "UNAUTH":
                findings.append(lead(
                    phase="azure_resources", check="kudu_unauth_exposed",
                    title=f"[!] Kudu UI EXPOSED UNAUTH: {host}",
                    target=f"https://{host}", severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                    description="Kudu / SCM deployment console returns the management UI without authentication. Direct code-exec primitive (zipdeploy, sshkey, env exfil).",
                    data={"host": host, "verdict": verdict, **info, "resource_type": "Kudu (UNAUTH)"},
                    tags=[ChainTag.AZ_KUDU_EXPOSED],
                    recommendation=(
                        "Immediately restrict SCM access via App Service Authentication "
                        "(Easy Auth), IP restrictions, or Private Endpoints. "
                        "Disable basic-auth publishing credentials. Rotate any deployment keys."
                    ),
                ))
            elif verdict == "EASYAUTH":
                findings.append(validation(
                    phase="azure_resources", check="kudu_easyauth_protected",
                    title=f"Kudu protected by AAD Easy Auth: {host}",
                    target=f"https://{host}",
                    payload={"host": host, "verdict": verdict, **info, "resource_type": "Kudu (Easy Auth)"},
                ))
            elif verdict == "401":
                findings.append(validation(
                    phase="azure_resources", check="kudu_basic_auth_required",
                    title=f"Kudu requires Basic auth: {host}",
                    target=f"https://{host}",
                    payload={"host": host, "verdict": verdict, **info, "resource_type": "Kudu (Basic auth)"},
                ))
            else:
                findings.append(lead(
                    phase="azure_resources", check="kudu_unknown_state",
                    title=f"Kudu reachable, auth state UNKNOWN: {host}",
                    target=f"https://{host}", severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                    description=f"Kudu /SCM responded {info.get('status')} but body did not match auth-redirect or unauth-UI markers — manual review.",
                    data={"host": host, "verdict": verdict, **info},
                    tags=[ChainTag.AZ_KUDU_EXPOSED],
                ))

    tasks = []
    for name in candidates:
        for suffix, label, tag, dns_definitive, codes in AZURE_HOST_PATTERNS:
            tasks.append(check(name, suffix, label, tag, dns_definitive, codes))
    await asyncio.gather(*tasks)

    # ---- Deep enumerate every confirmed Blob storage account ----
    blob_accounts: set[str] = set()
    for f in findings:
        if f.check == "az_blob_core_windows_net":
            host = f.data.get("host", "")
            if host.endswith(".blob.core.windows.net"):
                blob_accounts.add(host.split(".")[0])

    if blob_accounts:
        # Brand for attribution — derive from primary domain
        apex = (snap.primary_domain or ctx.target).lower()
        target_brand = apex.split(".")[0]
        for account in sorted(blob_accounts):
            try:
                deep_findings = await blob_deep.deep_enum_account(
                    http=http, account=account, om=om, workers=ctx.workers,
                    target_brand=target_brand,
                )
                findings.extend(deep_findings)
            except Exception:  # noqa: BLE001
                pass

    # ---- Azure DevOps org probe ----
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    for ado_org in {brand, snap.tenant_default_name and snap.tenant_default_name.replace(".onmicrosoft.com", "")}:
        if not ado_org:
            continue
        # dev.azure.com first
        url = f"https://dev.azure.com/{ado_org}"
        r = await http.head(url)
        if not r:
            r = await http.get(url)
        if r and r.status_code in (200, 203, 302, 401, 403):
            findings.append(data(
                phase="azure_resources", check="ado_org",
                title=f"Azure DevOps org may exist: {url}",
                target=url, confidence=Confidence.MEDIUM,
                payload={"resource_type": "Azure DevOps", "host": "dev.azure.com", "org": ado_org, "status": r.status_code},
                tags=[ChainTag.AZ_DEVOPS_ORG],
            ))
            # Public projects probe
            api = f"https://dev.azure.com/{ado_org}/_apis/projects?api-version=7.1-preview.4"
            pr = await http.get(api)
            if pr and pr.status_code == 200 and pr.text:
                try:
                    j = pr.json()
                    if j.get("count") and j.get("count") > 0:
                        om.save_raw(f"azure_resources/ado_projects_{ado_org}.json", str(j))
                        findings.append(lead(
                            phase="azure_resources", check="ado_public_projects",
                            title=f"Azure DevOps public projects in org `{ado_org}`",
                            target=api, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                            description=f"Anonymous access lists {j.get('count')} public project(s) in this ADO org. Source code, wikis, artifacts and pipelines may be exposed.",
                            data={"org": ado_org, "project_count": j.get("count"), "projects": [p.get("name") for p in j.get("value", [])]},
                            tags=[ChainTag.AZ_DEVOPS_PUBLIC_PROJECTS, ChainTag.AZ_DEVOPS_PUBLIC_WIKI],
                            recommendation="In Org Settings → Policies, disable 'Allow public projects' unless explicitly required. Review every public project for credentials, secrets, internal docs.",
                        ))
                except Exception:  # noqa: BLE001
                    pass

    return findings
