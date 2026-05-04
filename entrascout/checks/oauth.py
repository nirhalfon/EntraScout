"""Phase 7 — Token / OAuth recon (FOCI client probing, device-code surface)."""
from __future__ import annotations

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


# Family-of-Client-IDs — Microsoft's "first-party FOCI" clients
FOCI_CLIENTS = {
    "1b730954-1685-4b74-9bfd-dac224a7b894": "Microsoft Office (legacy)",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office (modern)",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams desktop",
    "00b41c95-dab0-4487-9791-b9d2c32c80f2": "Office 365 Management",
    "26a7ee05-5602-4d76-a7ba-eae8b7b67941": "Windows Search",
    "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
    "4813382a-8fa7-425e-ab75-3b753aab3abb": "Microsoft Authenticator",
    "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive Sync",
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1": "Visual Studio",
    "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online Client",
    "00000002-0000-0ff1-ce00-000000000000": "Office 365 Exchange Online",
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
}


async def probe_device_code(http: StealthClient, tenant_id: str, client_id: str) -> dict | None:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    r = await http.post(
        url,
        data={"client_id": client_id, "scope": "https://graph.microsoft.com/.default offline_access openid"},
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    if not r:
        return None
    try:
        return {"status": r.status_code, **r.json()}
    except Exception:  # noqa: BLE001
        return {"status": r.status_code, "raw": r.text[:300]}


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    if not snap.tenant_id:
        return findings

    # Device-code probe — many tenants leak the device-code surface for FOCI clients
    test_client = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"  # Teams desktop
    name = FOCI_CLIENTS.get(test_client, "Teams desktop")
    res = await probe_device_code(http, snap.tenant_id, test_client)
    if res and res.get("status") == 200 and res.get("user_code"):
        findings.append(lead(
            phase="oauth", check="device_code_active",
            title=f"Device-code flow reachable via FOCI client `{name}`",
            target=f"login.microsoftonline.com/{snap.tenant_id}/oauth2/v2.0/devicecode",
            severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
            description="Device code flow returns a user_code unauth — full surface for device-code phishing.",
            data={"client_id": test_client, "client_name": name, "verification_uri": res.get("verification_uri")},
            tags=[ChainTag.DEVICE_CODE_FLOW, ChainTag.FOCI_CLIENT_REACHABLE],
            recommendation="In Conditional Access, block device code flow for users who don't need it. Microsoft Learn: 'Block device code flow with Conditional Access.'",
        ))
    elif res:
        findings.append(data(
            phase="oauth", check="device_code_response",
            title=f"Device code response: HTTP {res.get('status')}",
            target=ctx.target, confidence=Confidence.MEDIUM,
            payload={"client_id": test_client, "client_name": name, "raw": res},
        ))

    return findings
