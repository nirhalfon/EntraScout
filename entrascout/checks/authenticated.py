"""Phase 34 — Authenticated Microsoft Graph probes.

Activates only when a Graph token is provided via `--token` CLI flag (the
existing `ctx.token` field). Runs deep recon that requires authentication:

- /me — caller identity confirmation
- /organization — tenant verified domains, tenant type
- /policies/identitySecurityDefaultsEnforcementPolicy — Security Defaults state
- /policies/authorizationPolicy — guest invite settings, default user role
- /policies/conditionalAccessPolicies — full CA dump (if reader role)
- /reports/credentialUserRegistrationDetails — MFA registration per user
  (the killer view: who has NOT registered MFA)
- /servicePrincipals — list all SPs
- /applications — app registrations
- /groups + /directoryRoles — privilege mapping

Read-only Graph queries. Token is never written to disk by EntraScout.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, issue, validation


GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


async def graph_get(http: StealthClient, url: str, token: str) -> dict | None:
    r = await http.get(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    if not r:
        return None
    if r.status_code == 200:
        try:
            return r.json()
        except Exception:
            return None
    return {"_error": True, "status": r.status_code, "body": (r.text or "")[:300]}


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    token = (getattr(ctx, "token", None) or "").strip()
    if not token:
        return findings  # silent skip when no token

    findings.append(data(
        phase="authenticated", check="authenticated_mode_active",
        title="Authenticated mode active — Graph token supplied",
        target=GRAPH_BASE, confidence=Confidence.HIGH,
        payload={"note": "Subsequent findings come from authenticated Graph queries."},
    ))

    # ---- /me ----
    me = await graph_get(http, f"{GRAPH_BASE}/me", token)
    if me and not me.get("_error"):
        findings.append(data(
            phase="authenticated", check="auth_me",
            title=f"Authenticated as: {me.get('userPrincipalName', '?')}",
            target=f"{GRAPH_BASE}/me", confidence=Confidence.HIGH,
            payload={
                "upn": me.get("userPrincipalName"),
                "displayName": me.get("displayName"),
                "id": me.get("id"),
                "jobTitle": me.get("jobTitle"),
            },
        ))

    # ---- /organization ----
    org = await graph_get(http, f"{GRAPH_BASE}/organization", token)
    if org and not org.get("_error") and (org.get("value") or []):
        o = org["value"][0]
        findings.append(data(
            phase="authenticated", check="auth_organization",
            title=f"Tenant: {o.get('displayName', '?')} ({o.get('id', '?')})",
            target=f"{GRAPH_BASE}/organization", confidence=Confidence.HIGH,
            payload={
                "tenant_id": o.get("id"),
                "name": o.get("displayName"),
                "verified_domains": [d.get("name") for d in o.get("verifiedDomains") or []],
                "country": o.get("countryLetterCode"),
                "directory_size_hint": o.get("directorySizeQuota", {}).get("used"),
            },
        ))

    # ---- Security Defaults ----
    sd = await graph_get(http, f"{GRAPH_BASE}/policies/identitySecurityDefaultsEnforcementPolicy", token)
    if sd and not sd.get("_error"):
        is_enabled = bool(sd.get("isEnabled"))
        if not is_enabled:
            findings.append(issue(
                phase="authenticated", check="security_defaults_disabled",
                title="Security Defaults are DISABLED — tenant relies on Conditional Access (verify CA coverage)",
                target=f"{GRAPH_BASE}/policies/identitySecurityDefaultsEnforcementPolicy",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description=(
                    "Security Defaults provides a baseline of Microsoft-managed MFA + legacy "
                    "auth blocking. When disabled, the tenant must replicate that protection "
                    "with Conditional Access Policies. Audit CA coverage."
                ),
                data={"isEnabled": False},
                tags=[ChainTag.MFA_GAP_DETECTED],
                recommendation="Either enable Security Defaults or ensure CA policies replicate equivalent protection.",
            ))
        else:
            findings.append(data(
                phase="authenticated", check="security_defaults_enabled",
                title="Security Defaults are ENABLED",
                target=f"{GRAPH_BASE}/policies/identitySecurityDefaultsEnforcementPolicy",
                confidence=Confidence.HIGH, payload={"isEnabled": True},
            ))

    # ---- Authorization policy (guest, default role, sign-up) ----
    ap = await graph_get(http, f"{GRAPH_BASE}/policies/authorizationPolicy", token)
    if ap and not ap.get("_error"):
        if isinstance(ap.get("value"), list) and ap["value"]:
            ap = ap["value"][0]
        invite = ap.get("allowInvitesFrom") or "(unknown)"
        guest_role = ap.get("guestUserRoleId") or "(unknown)"
        default_role = ap.get("defaultUserRolePermissions", {})
        findings.append(data(
            phase="authenticated", check="auth_authorization_policy",
            title=f"Authorization policy: invites={invite}, guest_role={guest_role}",
            target=f"{GRAPH_BASE}/policies/authorizationPolicy",
            confidence=Confidence.HIGH,
            payload={
                "allowInvitesFrom": invite,
                "guestUserRoleId": guest_role,
                "default_user_can_create_apps": default_role.get("allowedToCreateApps"),
                "default_user_can_create_security_groups": default_role.get("allowedToCreateSecurityGroups"),
                "default_user_can_read_other_users": default_role.get("allowedToReadOtherUsers"),
            },
        ))

    # ---- Conditional Access Policies (deep MFA-coverage map) ----
    cap = await graph_get(http, f"{GRAPH_BASE}/identity/conditionalAccess/policies", token)
    if cap and not cap.get("_error"):
        policies = cap.get("value") or []
        enabled = [p for p in policies if p.get("state") == "enabled"]
        report_only = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforced"]
        disabled = [p for p in policies if p.get("state") == "disabled"]
        findings.append(data(
            phase="authenticated", check="auth_ca_policies_summary",
            title=f"Conditional Access policies: {len(enabled)} enabled, {len(report_only)} report-only, {len(disabled)} disabled",
            target=f"{GRAPH_BASE}/identity/conditionalAccess/policies",
            confidence=Confidence.HIGH,
            payload={
                "total": len(policies),
                "enabled": len(enabled),
                "report_only": len(report_only),
                "disabled": len(disabled),
                "policy_names_enabled": [p.get("displayName") for p in enabled[:30]],
            },
        ))
        # Flag tenants with no enforced MFA-on-all-users policy
        any_mfa_all = any(
            p.get("conditions", {}).get("users", {}).get("includeUsers") == ["All"]
            and "mfa" in (p.get("grantControls") or {}).get("builtInControls", [])
            for p in enabled
        )
        if not any_mfa_all:
            findings.append(issue(
                phase="authenticated", check="ca_no_mfa_all_users",
                title="No enforced CA policy requires MFA for All Users",
                target=f"{GRAPH_BASE}/identity/conditionalAccess/policies",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                description=(
                    "Among enabled CA policies, none was found that includes 'All Users' "
                    "and requires MFA. This may be intentional (per-app MFA model) but "
                    "frequently indicates an MFA-coverage gap."
                ),
                data={"enabled_policy_count": len(enabled)},
                tags=[ChainTag.MFA_GAP_DETECTED],
            ))

    # ---- MFA registration report (KILLER VIEW) ----
    # /reports/credentialUserRegistrationDetails (legacy) or /reports/authenticationMethods/userRegistrationDetails (modern)
    mfa = await graph_get(
        http,
        f"{GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails?$top=999",
        token,
    )
    if mfa and not mfa.get("_error"):
        users = mfa.get("value") or []
        non_registered = [u for u in users if not u.get("isMfaRegistered")]
        admin_non_registered = [u for u in non_registered if u.get("isAdmin")]
        findings.append(data(
            phase="authenticated", check="auth_mfa_registration_report",
            title=f"MFA registration: {len(users)} users, {len(non_registered)} not registered, {len(admin_non_registered)} admins not registered",
            target=f"{GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails",
            confidence=Confidence.HIGH,
            payload={
                "total_users": len(users),
                "mfa_not_registered": len(non_registered),
                "admins_not_registered": len(admin_non_registered),
                "non_registered_sample": [u.get("userPrincipalName") for u in non_registered[:30]],
                "admin_non_registered_sample": [u.get("userPrincipalName") for u in admin_non_registered[:20]],
            },
            tags=[ChainTag.MFA_GAP_DETECTED] if non_registered else [],
        ))
        if admin_non_registered:
            findings.append(issue(
                phase="authenticated", check="ca_admin_without_mfa_registered",
                title=f"{len(admin_non_registered)} admin users have no MFA method registered",
                target=f"{GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                description=(
                    "Privileged users without MFA registration are a critical exposure. "
                    "Even with CA policies requiring MFA, a user without a registered method "
                    "may bypass via 'register MFA at sign-in' flow which itself is sometimes "
                    "skipped or attacker-controllable."
                ),
                data={"admins": [u.get("userPrincipalName") for u in admin_non_registered]},
                tags=[ChainTag.MFA_GAP_DETECTED],
                recommendation="Force MFA registration for all admin accounts; review privileged role assignments.",
            ))

    # ---- Service Principals (count + sample) ----
    sps = await graph_get(http, f"{GRAPH_BASE}/servicePrincipals?$top=999&$select=displayName,appId,appOwnerOrganizationId", token)
    if sps and not sps.get("_error"):
        items = sps.get("value") or []
        findings.append(data(
            phase="authenticated", check="auth_service_principals",
            title=f"Tenant has {len(items)} service principals (first 999)",
            target=f"{GRAPH_BASE}/servicePrincipals", confidence=Confidence.HIGH,
            payload={"count": len(items), "sample": [s.get("displayName") for s in items[:50]]},
        ))

    # ---- Applications ----
    apps = await graph_get(http, f"{GRAPH_BASE}/applications?$top=999&$select=displayName,appId,publisherDomain", token)
    if apps and not apps.get("_error"):
        items = apps.get("value") or []
        findings.append(data(
            phase="authenticated", check="auth_applications",
            title=f"Tenant has {len(items)} app registrations (first 999)",
            target=f"{GRAPH_BASE}/applications", confidence=Confidence.HIGH,
            payload={"count": len(items), "sample": [{"name": a.get("displayName"), "appId": a.get("appId")} for a in items[:50]]},
        ))

    # ---- Directory roles + members (privileged role mapping) ----
    roles = await graph_get(http, f"{GRAPH_BASE}/directoryRoles", token)
    if roles and not roles.get("_error"):
        rlist = roles.get("value") or []
        for r in rlist:
            rname = r.get("displayName", "")
            rid = r.get("id")
            if not rid:
                continue
            members = await graph_get(http, f"{GRAPH_BASE}/directoryRoles/{rid}/members", token)
            if members and not members.get("_error"):
                m_items = members.get("value") or []
                if m_items and rname.lower() in {"global administrator", "privileged role administrator", "security administrator", "application administrator"}:
                    findings.append(data(
                        phase="authenticated", check=f"auth_role_{rname.lower().replace(' ','_')}",
                        title=f"Role `{rname}` has {len(m_items)} members",
                        target=f"{GRAPH_BASE}/directoryRoles/{rid}/members",
                        confidence=Confidence.HIGH,
                        payload={"role": rname, "count": len(m_items),
                                 "members": [m.get("userPrincipalName") or m.get("displayName") for m in m_items]},
                    ))

    return findings
