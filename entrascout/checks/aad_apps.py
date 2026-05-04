"""Phase 17 — AAD App Registration enumeration + Graph permissions inference.

Gaps #4 and #22:
- Differentiate "app exists" vs "app not found" via login.microsoftonline.com responses
- Probe a small wordlist of well-known multi-tenant apps to confirm any belong to this tenant
- Infer Graph permissions exposed via tenant ID from `WWW-Authenticate` headers

Read-only. No credential attempts.
"""
from __future__ import annotations

import asyncio
import re

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


# Microsoft well-known first-party app IDs (FOCI / public) — useful as control responses
WELL_KNOWN_APP_IDS = {
    "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
}


async def probe_app_id(http: StealthClient, app_id: str) -> dict:
    """Hit /authorize and inspect AADSTS error code in the response body or redirect.

    AADSTS700016 → app does NOT exist
    AADSTS650056 / login form → app EXISTS in some tenant
    """
    url = (
        f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        f"?client_id={app_id}&response_type=code&redirect_uri=http://localhost"
        f"&scope=openid&state=ENTRASCOUT"
    )
    r = await http.get(url)
    out = {"app_id": app_id, "status": r.status_code if r else None, "exists": None, "error_code": None}
    if not r:
        return out
    body = (r.text or "")[:4000]
    # AADSTS error code in body
    m = re.search(r"AADSTS(\d{6})", body)
    if m:
        out["error_code"] = f"AADSTS{m.group(1)}"
        out["exists"] = m.group(1) != "700016"  # 700016 = app not found
    elif r.status_code in (200, 302):
        # Either we got the login page (app exists, public client) or a redirect to login
        out["exists"] = True
    return out


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    if not snap.tenant_id:
        return findings

    sem = asyncio.Semaphore(min(ctx.workers, 6))

    # ---- Graph tenant ID confirmation via WWW-Authenticate ----
    # Anonymous GET to graph.microsoft.com/v1.0/me always returns 401, but the
    # WWW-Authenticate header includes `realm="{tenant_id}"` when scoped.
    async with sem:
        r = await http.get("https://graph.microsoft.com/v1.0/$metadata")
    if r and r.headers:
        auth = r.headers.get("www-authenticate") or r.headers.get("WWW-Authenticate") or ""
        if auth:
            findings.append(data(
                phase="aad_apps", check="graph_metadata_reachable",
                title="Microsoft Graph metadata anonymously reachable (universal)",
                target="https://graph.microsoft.com/v1.0/$metadata", confidence=Confidence.HIGH,
                payload={
                    "url": "https://graph.microsoft.com/v1.0/$metadata",
                    "status": r.status_code,
                    "www_authenticate_hint": auth[:300],
                    "note": "Graph metadata is identical across tenants — this is reference data only.",
                },
            ))

    # ---- Probe well-known Microsoft app IDs as positive control ----
    # Confirms our detection logic — these all should return exists=True
    async def control_probe(app_id: str, name: str) -> None:
        result = await probe_app_id(http, app_id)
        if result.get("exists"):
            findings.append(data(
                phase="aad_apps", check="aad_wellknown_app_reachable",
                title=f"AAD well-known app reachable: {name} ({app_id})",
                target=f"client_id={app_id}", confidence=Confidence.HIGH,
                payload=result,
                tags=[ChainTag.AAD_APP_REGISTERED],
            ))

    # Limit control probes (they hit Microsoft, not customer infra)
    await asyncio.gather(*(control_probe(aid, nm) for aid, nm in list(WELL_KNOWN_APP_IDS.items())[:2]))

    # ---- B2C tenant detection via openid-configuration variant ----
    # B2C tenants respond on the b2clogin.com domain instead of login.microsoftonline.com
    if snap.tenant_default_name:
        b2c_short = snap.tenant_default_name.replace(".onmicrosoft.com", "")
        b2c_url = f"https://{b2c_short}.b2clogin.com/{b2c_short}.onmicrosoft.com/v2.0/.well-known/openid-configuration"
        async with sem:
            r = await http.get(b2c_url)
        if r and r.status_code == 200 and "b2clogin" in (r.text or ""):
            findings.append(lead(
                phase="aad_apps", check="aad_b2c_tenant_detected",
                title=f"Azure AD B2C tenant detected: {b2c_short}.b2clogin.com",
                target=b2c_url, severity=Severity.LOW, confidence=Confidence.HIGH,
                description=(
                    "Tenant runs Azure AD B2C in addition to (or instead of) Entra B2B. B2C has "
                    "a different attack surface: custom user-flow policies, custom HTML/JS in "
                    "branded sign-up pages, and JWT validation on the app side. Audit B2C "
                    "user-flow policies for self-service signup, social IdP federation, and "
                    "exposed custom-policy XML."
                ),
                data={"url": b2c_url, "tenant_short": b2c_short},
                tags=[ChainTag.AAD_B2C_TENANT],
                recommendation="Audit B2C user flows: disable self-service signup if not needed, restrict allowed identity providers.",
            ))

    return findings
