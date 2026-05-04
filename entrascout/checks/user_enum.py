"""Phase 3 — User enumeration via multiple cross-validated channels."""
from __future__ import annotations

import asyncio
import time
from typing import Any

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, issue, lead


async def get_credential_type(http: StealthClient, login: str) -> dict | None:
    url = "https://login.microsoftonline.com/common/GetCredentialType"
    body = {
        "username": login,
        "isOtherIdpSupported": True,
        "checkPhones": False,
        "isRemoteNGCSupported": True,
        "isCookieBannerShown": False,
        "isFidoSupported": True,
        "originalRequest": "",
        "country": "US",
    }
    r = await http.post(
        url,
        json=body,
        headers={"Accept": "application/json", "Content-Type": "application/json; charset=UTF-8"},
    )
    if not r:
        return None
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return None


async def onedrive_user_probe(http: StealthClient, tenant_default: str, login: str) -> int | None:
    """OneDrive timing/status diff. Pattern: tenant-my.sharepoint.com/personal/{user}_{domain}_com/.

    Returns response status (404 = not exists; 401/403 = exists)."""
    if "@" not in login:
        return None
    user, domain = login.split("@", 1)
    domain_part = domain.replace(".", "_")
    url = f"https://{tenant_default}-my.sharepoint.com/personal/{user}_{domain_part}/_layouts/15/onedrive.aspx"
    r = await http.get(url)
    return r.status_code if r else None


async def teams_external_search(http: StealthClient, login: str) -> dict | None:
    """Teams external search — only works if target tenant has external chat enabled.

    Endpoint: teams.microsoft.com/api/mt/{region}/beta/users/.../externalsearchv3
    """
    # The region is variable; emea works for many. WW falls back if region is unknown.
    for region in ("emea", "amer", "apac"):
        url = f"https://teams.microsoft.com/api/mt/{region}/beta/users/{login}/externalsearchv3"
        r = await http.get(url)
        if not r:
            continue
        if r.status_code in (200, 404):
            try:
                return {"status": r.status_code, "json": r.json(), "region": region}
            except Exception:  # noqa: BLE001
                return {"status": r.status_code, "raw": r.text[:500], "region": region}
    return None


def _users_to_check(ctx: RunContext, snap: TenantSnapshot) -> list[str]:
    domain = snap.primary_domain or ctx.target
    candidates: list[str] = []
    if ctx.user_hint:
        candidates.append(ctx.user_hint)
    # A small built-in candidate list — names that often exist
    common_names = [
        "admin", "administrator", "info", "support", "helpdesk", "hr", "finance",
        "ceo", "cfo", "cto", "ciso", "it", "marketing", "sales", "noreply", "no-reply",
        "test", "dev", "security", "office",
    ]
    candidates.extend(f"{n}@{domain}" for n in common_names)
    return candidates


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    candidates = _users_to_check(ctx, snap)
    if not candidates:
        return findings

    # ---- 1. GetCredentialType (passive, low-noise) ----
    sem = asyncio.Semaphore(min(ctx.workers, 16))
    results: dict[str, dict[str, Any]] = {}

    # ---- 1a. CONTROL probe — ensure tenant is enum-able ----
    # If a guaranteed-fake username also returns "valid", the tenant either has
    # anti-enum / federated black-hole behavior, and the enum is unreliable.
    domain = (snap.primary_domain or ctx.target).lower()
    import secrets as _secrets
    control_login = f"zzfake{_secrets.token_hex(6)}@{domain}"
    control_r = await get_credential_type(http, control_login)
    control_ifexists = control_r.get("IfExistsResult", -1) if control_r else -1
    enum_unreliable = control_ifexists in (0, 5, 6)
    # 0 = "exists" returned for fake → tenant says everyone exists (anti-enum / federated)
    # 5 = "federated" returned for fake → handing off to ADFS regardless
    # 6 = throttled → can't trust any answers

    async def probe_gct(login: str) -> None:
        async with sem:
            r = await get_credential_type(http, login)
            if not r:
                return
            valid = r.get("IfExistsResult", -1) == 0  # 0 = exists
            mfa_hint = r.get("EstsProperties", {}).get("UserTenantBranding") is not None
            results[login] = {
                "method": "GetCredentialType",
                "valid": valid,
                "ifExistsResult": r.get("IfExistsResult"),
                "throttleStatus": r.get("ThrottleStatus"),
                "mfaProperties": r.get("Credentials", {}),
                "estsProperties": bool(r.get("EstsProperties")),
                "mfa_hint": mfa_hint,
            }

    await asyncio.gather(*(probe_gct(c) for c in candidates))

    valid_users = [u for u, info in results.items() if info.get("valid")]
    invalid_users = [u for u, info in results.items() if info.get("valid") is False]

    if enum_unreliable:
        # Tenant blackholes user-enum — emit ONE finding describing it, no individual users
        findings.append(data(
            phase="user_enum", check="user_enum_unreliable_tenant",
            title=f"GetCredentialType enum unreliable on this tenant (control returned IfExistsResult={control_ifexists})",
            target=ctx.target, confidence=Confidence.HIGH,
            payload={
                "control_username": control_login,
                "control_ifexists_result": control_ifexists,
                "interpretation": {
                    0: "Tenant returns 'exists' for ANY username — anti-enum / federated black-hole. Do NOT trust GetCredentialType results from this tenant.",
                    5: "Tenant returns 'federated' for ANY username — auth handed off to ADFS regardless. GetCredentialType pre-auth signal is meaningless here.",
                    6: "Tenant is throttling — retry later from a different source IP.",
                }.get(control_ifexists, "unknown"),
                "candidates_probed": len(candidates),
                "candidates_marked_valid_FALSE_POSITIVES": len(valid_users),
                "next_steps": [
                    "Use OneDrive timing-channel enum instead (still works on most tenants)",
                    "Use Teams external-search enum (requires API key)",
                    "Cross-validate any 'valid' users via a second method before trusting",
                ],
            },
            tags=[ChainTag.USER_ENUM_GETCREDTYPE],
        ))
        # Do NOT emit individual user findings or summary — they are unreliable
    else:
        for u, info in results.items():
            if info["valid"]:
                findings.append(data(
                    phase="user_enum", check="user_enum_getcredtype",
                    title=f"Valid user (GetCredentialType): {u}",
                    target=u, confidence=Confidence.HIGH,
                    payload={"user": u, "valid": True, "method": "GetCredentialType",
                             "throttleStatus": info.get("throttleStatus")},
                    tags=[ChainTag.USER_ENUM_GETCREDTYPE],
                ))

        if valid_users:
            findings.append(lead(
                phase="user_enum", check="user_enum_summary",
                title=f"{len(valid_users)} candidate users validated via GetCredentialType",
                target=ctx.target, severity=Severity.LOW, confidence=Confidence.HIGH,
                description="Confirmed valid login identifiers — useful for password spray, phishing, MFA fatigue.",
                data={"valid_count": len(valid_users), "valid_users": valid_users,
                      "control_login": control_login, "control_ifexists_result": control_ifexists},
                tags=[ChainTag.USER_ENUM_GETCREDTYPE],
                recommendation="Username enumeration via GetCredentialType is by-design and cannot be fully blocked. Reduce risk by enforcing MFA, conditional access, Smart Lockout, and password policy.",
            ))

    # ---- 2. OneDrive cross-validation (only if we have a tenant default name) ----
    if snap.tenant_default_name and valid_users:
        tenant_short = snap.tenant_default_name.replace(".onmicrosoft.com", "")
        async def probe_od(login: str) -> tuple[str, int | None]:
            async with sem:
                code = await onedrive_user_probe(http, tenant_short, login)
                return login, code

        od_results = await asyncio.gather(*(probe_od(u) for u in valid_users[:25]))
        confirmed_n_plus: list[str] = []
        for login, code in od_results:
            if code in (401, 403, 200):
                confirmed_n_plus.append(login)
                findings.append(data(
                    phase="user_enum", check="user_enum_onedrive",
                    title=f"OneDrive confirms: {login}",
                    target=login, confidence=Confidence.HIGH,
                    payload={"user": login, "valid": True, "method": "OneDrive", "status": code},
                    tags=[ChainTag.USER_ENUM_ONEDRIVE],
                ))

        if confirmed_n_plus:
            findings.append(lead(
                phase="user_enum", check="user_enum_nplus",
                title=f"{len(confirmed_n_plus)} users confirmed by ≥2 sources",
                target=ctx.target, severity=Severity.LOW, confidence=Confidence.CONFIRMED,
                description="High-confidence valid usernames (cross-validated by GetCredentialType and OneDrive). Low false-positive rate for spray.",
                data={"users": confirmed_n_plus},
                tags=[ChainTag.USER_VALIDATED_NPLUS],
            ))

    # ---- 3. Teams external (only if presence APIs reachable) ----
    if valid_users:
        sample = valid_users[:5]
        for u in sample:
            tres = await teams_external_search(http, u)
            if tres and tres.get("status") == 200:
                findings.append(data(
                    phase="user_enum", check="user_enum_teams",
                    title=f"Teams external search reveals: {u}",
                    target=u, confidence=Confidence.HIGH,
                    payload={"user": u, "method": "Teams-external-search", **tres},
                    tags=[ChainTag.USER_ENUM_TEAMS],
                ))
                # If we got a 200 here with actual data it means external Teams chat is OPEN
                findings.append(lead(
                    phase="user_enum", check="teams_external_chat_open",
                    title="Teams external federation/chat is open — anonymous user lookup possible",
                    target=ctx.target, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                    description="External Teams chat federation appears to allow lookups from outside the tenant. Phishing surface — attackers can DM employees from arbitrary external tenants.",
                    tags=[ChainTag.USER_ENUM_TEAMS],
                    recommendation="In Teams Admin → External access, consider blocking by default and allowing only specific federated tenants. Apply CA policy 'External users must MFA' for guest invitations.",
                ))
                break

    return findings
