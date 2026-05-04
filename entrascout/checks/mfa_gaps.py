"""Phase 31 — MFA bypass / gap surface mapper.

Hunts for authentication endpoints that bypass or under-enforce MFA. Each
finding is the *presence* of a surface; whether MFA is *actually* skipped on
that surface depends on per-RP / per-app Conditional Access policies that we
cannot probe anonymously without authenticating. The finding documents the
exposure and the conditions under which it becomes an MFA bypass.

Endpoints checked:
- ADFS WS-Trust /usernamemixed (basic auth, no MFA in default config)
- ADFS WS-Trust /windowstransport (Kerberos, no MFA)
- ADFS WS-Trust /certificatemixed (cert auth, may skip MFA)
- Exchange Online basic-auth surfaces:
  - /EWS/Exchange.asmx (Exchange Web Services)
  - /Microsoft-Server-ActiveSync
  - /Autodiscover/Autodiscover.xml
  - /OAB
  - /MAPI/emsmdb
- AAD legacy endpoints with weaker MFA enforcement:
  - oauth2/token (v1, ROPC — Resource Owner Password Credential flow)
  - oauth2/v2.0/token (v2 ROPC)
  - oauth2/devicecode (device code flow)
- SMTP AUTH (outlook.office365.com:587)
- IMAP/POP3 ports

Read-only existence checks. Combined with `defense_posture` and `auth_surface`
for the full MFA-gap roll-up.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, issue, is_existence_signal


# (path, label, severity, why)
EXO_LEGACY_AUTH_PATHS = [
    ("/EWS/Exchange.asmx",
     "Exchange Web Services (EWS)",
     Severity.MEDIUM,
     "EWS supports both modern auth (OAuth) and legacy basic auth. If the tenant has not "
     "disabled basic auth, EWS Basic accepts user/password without MFA, and is the most "
     "common exfiltration channel for compromised mailboxes."),
    ("/Microsoft-Server-ActiveSync",
     "Exchange ActiveSync (mobile mail protocol)",
     Severity.MEDIUM,
     "ActiveSync historically authenticated with basic auth. Legacy mobile clients still "
     "use this. Basic auth on ActiveSync = MFA bypass for any user whose phone is enrolled."),
    ("/Autodiscover/Autodiscover.xml",
     "Autodiscover (mail client config) — sometimes accepts WS-Trust legacy auth",
     Severity.LOW,
     "Autodiscover delegates auth to MEX/WS-Trust and may accept legacy auth tokens."),
    ("/OAB",
     "Offline Address Book (OAB) endpoint",
     Severity.LOW,
     "OAB is downloaded by Outlook and traditionally authenticates via basic auth."),
    ("/MAPI/emsmdb",
     "MAPI over HTTP",
     Severity.LOW,
     "MAPI/HTTP supports both modern and basic auth; legacy clients use basic."),
    ("/PowerShell-LiveID",
     "Exchange Online Remote PowerShell endpoint",
     Severity.LOW,
     "Legacy Remote PowerShell to Exchange Online. Modern auth requires V3 module; legacy V2 used basic auth."),
]


# Endpoints that should ALWAYS exist on EXO — finding them confirms tenant uses EXO,
# the SEVERITY is whether they accept basic auth (we can't tell anonymously, but flag the surface)
EXO_HOST_VARIANTS = [
    "outlook.office365.com",
    "outlook.office.com",
]


# AAD legacy auth endpoints — these are the same for every tenant, but flagging
# them in the report is useful as the baseline reference.
AAD_LEGACY_TOKEN_FLOWS = [
    ("oauth2/token",
     "AAD OAuth2 v1 token endpoint — supports ROPC (Resource Owner Password Credential) which always bypasses MFA",
     Severity.HIGH),
    ("oauth2/v2.0/token",
     "AAD OAuth2 v2 token endpoint — supports ROPC; v2 has same MFA-bypass property as v1",
     Severity.HIGH),
    ("oauth2/devicecode",
     "AAD device code flow — different MFA enforcement profile than browser flows",
     Severity.MEDIUM),
]


async def head_existence(http: StealthClient, url: str) -> int | None:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    return r.status_code if r else None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()

    sem = asyncio.Semaphore(min(ctx.workers, 8))

    # ---- 1. Exchange Online legacy-auth surfaces ----
    async def probe_exo(path: str, label: str, severity: Severity, why: str, host: str) -> None:
        url = f"https://{host}{path}"
        async with sem:
            code = await head_existence(http, url)
        # 401/200/302/404 are all observed — 401 typically means the endpoint exists and requires auth
        if code in (200, 302, 401, 405):
            findings.append(lead(
                phase="mfa_gaps", check=f"exo_legacy_auth_{path.strip('/').replace('/','_')}",
                title=f"EXO legacy-auth surface present: {label}",
                target=url, severity=severity, confidence=Confidence.MEDIUM,
                description=(
                    f"{why}\n\nExchange Online endpoint `{path}` returned {code} on "
                    f"`{host}`. We cannot confirm anonymously whether basic auth is enabled "
                    f"on this endpoint for this tenant — that requires looking at "
                    f"`Set-OrganizationConfig -OAuth2ClientProfileEnabled` (auth required) or "
                    f"observing 401 vs 403 differential when attempting basic auth."
                ),
                data={"url": url, "endpoint": path, "host": host, "status": code,
                      "label": label,
                      "verification": "Authenticated check via ExchangeOnline PowerShell: Get-AuthenticationPolicy | fl"},
                tags=[ChainTag.LEGACY_AUTH_EWS_BASIC if "EWS" in label else ChainTag.MFA_GAP_DETECTED],
                recommendation=(
                    "Disable basic auth: `Set-OrganizationConfig -OAuthClientProfileEnabled $false`. "
                    "Apply CA policies that block legacy auth at sign-in."
                ),
            ))

    for host in EXO_HOST_VARIANTS[:1]:  # only probe one host — they share infra
        await asyncio.gather(*(probe_exo(p, lbl, sev, why, host) for p, lbl, sev, why in EXO_LEGACY_AUTH_PATHS))

    # ---- 2. Autodiscover on the org's actual domain ----
    autod_url = f"https://autodiscover.{apex}/Autodiscover/Autodiscover.xml"
    code = await head_existence(http, autod_url)
    if code in (200, 302, 401):
        findings.append(data(
            phase="mfa_gaps", check="org_autodiscover_reachable",
            title=f"Org-domain Autodiscover reachable: {autod_url}",
            target=autod_url, confidence=Confidence.HIGH,
            payload={"url": autod_url, "status": code,
                     "note": "Autodiscover responses can leak hybrid configuration & internal hostnames; legacy clients use it for auth bootstrap."},
            tags=[ChainTag.LEGACY_AUTH_EWS_BASIC],
        ))

    # ---- 3. ADFS — additional MFA-bypass-relevant endpoints ----
    # Derive ADFS host from snap.auth_url if present (e.g. https://corp.sts.ford.com/adfs/ls/...)
    adfs_h = ""
    auth_url = (snap.auth_url or "")
    if auth_url and "//" in auth_url:
        try:
            adfs_h = auth_url.split("//")[1].split("/")[0]
        except Exception:
            adfs_h = ""
    if adfs_h:
        adfs_paths = [
            ("/adfs/services/trust/2005/usernamemixed",
             "WS-Trust 2005 username/password mixed — no MFA in default ADFS config",
             Severity.HIGH,
             ChainTag.FED_ADFS_DETECTED),
            ("/adfs/services/trust/13/usernamemixed",
             "WS-Trust 1.3 username/password mixed — same MFA bypass property",
             Severity.HIGH,
             ChainTag.FED_ADFS_DETECTED),
            ("/adfs/services/trust/2005/windowstransport",
             "WS-Trust Windows transport (Kerberos / NTLM) — typically MFA-exempt for service accounts",
             Severity.MEDIUM,
             ChainTag.FED_ADFS_DETECTED),
        ]

        async def probe_adfs(path: str, why: str, sev: Severity, tag: ChainTag) -> None:
            url = f"https://{adfs_h}{path}"
            async with sem:
                code = await head_existence(http, url)
            if code in (200, 401, 405, 415):
                findings.append(lead(
                    phase="mfa_gaps", check=f"adfs_legacy_{path.split('/trust/')[-1].replace('/','_')}",
                    title=f"ADFS legacy-auth surface: {url}",
                    target=url, severity=sev, confidence=Confidence.HIGH,
                    description=why,
                    data={"url": url, "path": path, "status": code, "adfs_host": adfs_h},
                    tags=[tag, ChainTag.MFA_GAP_DETECTED],
                    recommendation=(
                        "Enforce MFA at the RP level (`Set-AdfsRelyingPartyTrust`) "
                        "for any RP federated against this ADFS. Audit "
                        "`Get-AdfsAuthenticationProvider` for missing MFA providers."
                    ),
                ))

        await asyncio.gather(*(probe_adfs(p, w, s, t) for p, w, s, t in adfs_paths))

    # ---- 4. AAD legacy token flows — universal endpoints, but document them ----
    findings.append(data(
        phase="mfa_gaps", check="aad_legacy_token_flow_inventory",
        title="AAD legacy token-flow inventory (ROPC / device code) — universal endpoints",
        target=f"https://login.microsoftonline.com/{apex}/oauth2/", confidence=Confidence.HIGH,
        payload={
            "ropc_v1": f"https://login.microsoftonline.com/{apex}/oauth2/token",
            "ropc_v2": f"https://login.microsoftonline.com/{apex}/oauth2/v2.0/token",
            "devicecode": f"https://login.microsoftonline.com/{apex}/oauth2/v2.0/devicecode",
            "note": "ROPC always bypasses MFA by design — no challenge can be issued in a non-interactive flow. "
                    "Modern guidance is to BLOCK ROPC via Conditional Access. Verify with: "
                    "Get-MgConditionalAccessPolicy | Where-Object { $_.Conditions.ClientApplications.IncludeApplications -contains 'all' -and $_.GrantControls.BuiltInControls -contains 'mfa' }",
        },
        tags=[ChainTag.MFA_GAP_DETECTED],
    ))

    # ---- 5. SMTP AUTH / IMAP / POP3 — already covered by auth_surface for legacy-banner detection ----
    # We don't duplicate; auth_surface flags those ports as findings already.

    return findings
