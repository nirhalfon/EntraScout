"""Phase 14 — Identity / device / CA edges (App Proxy, MCAS, DRS)."""
from __future__ import annotations

import asyncio

from ..dns_client import query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, issue, lead


async def head(http: StealthClient, url: str) -> int | None:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    return r.status_code if r else None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand

    # ---- AAD App Proxy (msappproxy.net) ----
    candidates = {brand, tenant_short, f"{brand}-app", f"{brand}-portal", f"{brand}-internal", f"{brand}-vpn"}
    sem = asyncio.Semaphore(ctx.workers)

    async def probe_appproxy(name: str) -> None:
        host = f"{name}.msappproxy.net"
        async with sem:
            recs = await query(host, "A") or await query(host, "CNAME")
        if not recs:
            return
        # `*.msappproxy.net` does NOT have wildcard DNS — DNS resolving means the
        # name was actually published. But "published" can mean "registered, no
        # backend assigned". Probe HTTP and downgrade severity if it 404s/no-content.
        code = await head(http, f"https://{host}")
        if not code:
            # No HTTP at all → mark as registered but unverified
            severity = Severity.LOW
            description = "DNS-published `*.msappproxy.net` name with no HTTP response — registered slot, may be parked or pre-auth blocking."
        elif code == 404:
            severity = Severity.LOW
            description = "DNS-published `*.msappproxy.net` name returns 404 — name registered but backend unconfigured or pre-auth blocking."
        elif code in (302, 401, 403):
            severity = Severity.MEDIUM
            description = "AAD App Proxy publication with auth gate. Likely pre-auth=AAD; user reaches login. Worth follow-up post-cred."
        elif code in (200, 301, 503):
            severity = Severity.HIGH
            description = "AAD App Proxy publication serves content unauthenticated! Likely pre-auth=passthrough — direct attack against internal app."
        else:
            severity = Severity.MEDIUM
            description = f"AAD App Proxy publication responded {code} — manual review."
        findings.append(lead(
            phase="identity_edges", check="app_proxy_published",
            title=f"AAD App Proxy: {host} (HTTP {code or 'no response'})",
            target=f"https://{host}", severity=severity, confidence=Confidence.HIGH,
            description=description,
            data={"resource_type": "AAD App Proxy", "host": host, "dns": recs, "status": code},
            tags=[ChainTag.APP_PROXY_PUBLIC],
            recommendation=(
                "Audit each App Proxy app: ensure pre-auth via AAD is enforced (NOT passthrough), "
                "the published on-prem app is patched, and consider Conditional Access on the "
                "published app. Even auth-gated App Proxy hosts leak the existence of internal "
                "apps and brand them on the internet — review whether each publication is still needed."
            ),
        ))

    await asyncio.gather(*(probe_appproxy(c) for c in candidates))

    # ---- MCAS / Defender for Cloud Apps tenant URL ----
    mcas_host = f"{tenant_short}.portal.cloudappsecurity.com"
    code = await head(http, f"https://{mcas_host}")
    if code and code in (200, 302, 401, 403):
        findings.append(data(
            phase="identity_edges", check="mcas_tenant",
            title=f"Microsoft Defender for Cloud Apps tenant detected: {mcas_host}",
            target=f"https://{mcas_host}", confidence=Confidence.HIGH,
            payload={"resource_type": "MCAS / Defender for Cloud Apps", "host": mcas_host, "status": code},
            tags=[ChainTag.MCAS_TENANT],
        ))

    # ---- enterpriseregistration / enterpriseenrollment surfaces ----
    for prefix, label in [("enterpriseregistration", "AAD Device Registration Service"),
                          ("enterpriseenrollment", "Intune Enrollment Service")]:
        recs = await query(f"{prefix}.{apex}", "CNAME") or await query(f"{prefix}.{apex}", "A")
        if recs:
            findings.append(data(
                phase="identity_edges", check=f"drs_{prefix}",
                title=f"{label} CNAME present at {prefix}.{apex}",
                target=f"{prefix}.{apex}", confidence=Confidence.HIGH,
                payload={"resource_type": label, "host": f"{prefix}.{apex}", "dns": recs},
            ))

    # ---- Cross-tenant access via B2B invitation flow probing ----
    # This is a soft heuristic — we issue an authorize request asking for a B2B invite,
    # the OAuth error code differential reveals if invitations are blocked or open.
    if snap.tenant_id:
        # Probe: try to start an invite redemption via /common/oauth2/v2.0/authorize
        # with prompt=consent and a guest-style state. The 'AADSTSxxxxx' codes returned
        # leak CTAP allow/block posture.
        url = (
            f"https://login.microsoftonline.com/{snap.tenant_id}/oauth2/v2.0/authorize"
            f"?client_id=00000003-0000-0000-c000-000000000000"
            f"&response_type=code&redirect_uri=https%3A%2F%2Flocalhost"
            f"&scope=openid&prompt=consent&login_hint=guest@external.invalid"
        )
        r = await http.get(url)
        if r and r.status_code:
            text_lower = (r.text or "").lower()
            inferred = None
            if "aadsts65001" in text_lower:
                inferred = "B2B invitations may be allowed (consent flow reachable)"
            elif "aadsts70001" in text_lower:
                inferred = "App not registered — limited info"
            elif "aadsts53003" in text_lower or "policy" in text_lower:
                inferred = "Conditional Access policy intercepts external auth"
            if inferred:
                findings.append(data(
                    phase="identity_edges", check="ctap_inference",
                    title=f"CTAP / external-auth posture inferred: {inferred}",
                    target=apex, confidence=Confidence.LOW,
                    payload={"resource_type": "CTAP heuristic", "host": "login.microsoftonline.com",
                             "status": r.status_code, "inferred": inferred},
                    tags=[ChainTag.CTAP_INFERRED],
                ))

    return findings
