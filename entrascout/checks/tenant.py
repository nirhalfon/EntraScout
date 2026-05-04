"""Phase 1 — Tenant fingerprint (passive, zero-noise)."""
from __future__ import annotations

import re
from typing import Any

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import GUID_RE, data, issue, lead, validation


CLOUD_ISSUER_MAP = {
    "login.microsoftonline.com": ("Public", "WW"),
    "login.microsoftonline.us": ("GCC-High/DoD", "USGov"),
    "login.microsoftonline.de": ("Germany (legacy)", "DE"),
    "login.partner.microsoftonline.cn": ("China (21Vianet)", "CN"),
    "login.microsoftonline.mil": ("DoD", "USGov"),
}


async def get_oidc_config(http: StealthClient, domain: str) -> tuple[dict[str, Any] | None, str | None]:
    url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
    r = await http.get(url)
    if not r or r.status_code >= 400:
        return None, None
    try:
        return r.json(), r.text
    except Exception:  # noqa: BLE001
        return None, r.text


async def get_userrealm(http: StealthClient, login: str) -> dict[str, Any] | None:
    url = f"https://login.microsoftonline.com/getuserrealm.srf?login={login}&xml=0"
    r = await http.get(url, headers={"Accept": "application/json"})
    if not r or r.status_code >= 400:
        return None
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return None


async def get_userrealm_v21(http: StealthClient, login: str) -> dict[str, Any] | None:
    url = f"https://login.microsoftonline.com/common/userrealm/{login}?api-version=2.1"
    r = await http.get(url, headers={"Accept": "application/json"})
    if not r or r.status_code >= 400:
        return None
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return None


async def get_login_branding(http: StealthClient, tenant_id: str) -> str | None:
    url = (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        f"?client_id=00000003-0000-0000-c000-000000000000"
        f"&response_type=code&redirect_uri=https%3A%2F%2Flocalhost"
        f"&scope=openid&prompt=login"
    )
    r = await http.get(url)
    if not r:
        return None
    return r.text


def _extract_branding(html: str) -> dict[str, Any]:
    """Scrape display name / logo / bg from the login page HTML."""
    out: dict[str, Any] = {}
    for key, pattern in [
        ("company_name", r'"BannerLogo":"[^"]+","TileLogo"[^}]*"BannerName":"([^"]+)"'),
        ("logo_url", r'"BannerLogo":"([^"]+)"'),
        ("background_url", r'"BackgroundImage":"([^"]+)"'),
        ("tile_logo", r'"TileLogo":"([^"]+)"'),
        ("tile_dark_logo", r'"TileDarkLogo":"([^"]+)"'),
        ("user_id_label", r'"UserIdLabel":"([^"]+)"'),
        ("sign_in_page_text", r'"BoilerPlateText":"([^"]+)"'),
        ("color", r'"BackgroundColor":"([^"]+)"'),
    ]:
        m = re.search(pattern, html)
        if m:
            out[key] = m.group(1).encode().decode("unicode_escape")
    return out


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    domain = ctx.target

    # ---- 1. OIDC ----
    oidc, raw = await get_oidc_config(http, domain)
    if not oidc:
        findings.append(issue(
            phase="tenant", check="oidc_lookup",
            title="Tenant OIDC config not reachable for this domain",
            target=domain, severity=Severity.LOW, confidence=Confidence.HIGH,
            description="The .well-known/openid-configuration endpoint returned no usable data — domain may not be M365.",
            recommendation="Confirm the domain is correct. If they are M365 customers, this is unusual and worth investigating.",
        ))
        return findings

    if raw:
        ev = om.save_raw(f"tenant/oidc_{domain}.json", raw)
    issuer = oidc.get("issuer", "")
    tenant_id = None
    m = GUID_RE.search(issuer)
    if m:
        tenant_id = m.group(0).lower()

    snap.primary_domain = domain
    snap.tenant_id = tenant_id
    snap.issuer = issuer

    # Tenant region / cloud
    auth_endpoint = oidc.get("authorization_endpoint", "")
    cloud_host = ""
    for known in CLOUD_ISSUER_MAP:
        if known in auth_endpoint or known in issuer:
            cloud_host = known
            snap.tenant_cloud, snap.tenant_region = CLOUD_ISSUER_MAP[known]
            break

    findings.append(data(
        phase="tenant", check="oidc",
        title=f"Tenant confirmed: {tenant_id or 'unknown-id'}",
        target=domain, confidence=Confidence.CONFIRMED,
        payload={
            "tenant_id": tenant_id,
            "issuer": issuer,
            "auth_endpoint": auth_endpoint,
            "token_endpoint": oidc.get("token_endpoint", ""),
            "device_auth_endpoint": oidc.get("device_authorization_endpoint", ""),
            "userinfo_endpoint": oidc.get("userinfo_endpoint", ""),
            "jwks_uri": oidc.get("jwks_uri", ""),
            "tenant_region_scope": oidc.get("tenant_region_scope", ""),
            "tenant_region_sub_scope": oidc.get("tenant_region_sub_scope", ""),
            "cloud_instance_name": oidc.get("cloud_instance_name", ""),
            "cloud_graph_host_name": oidc.get("cloud_graph_host_name", ""),
            "msgraph_host": oidc.get("msgraph_host", ""),
            "rbac_url": oidc.get("rbac_url", ""),
            "kerberos_endpoint": oidc.get("kerberos_endpoint", ""),
        },
        tags=[ChainTag.TENANT_CONFIRMED, ChainTag.TENANT_REGION_KNOWN] if tenant_id else [ChainTag.TENANT_CONFIRMED],
    ))

    # Device-code flow (FOCI surface)
    if oidc.get("device_authorization_endpoint"):
        findings.append(lead(
            phase="tenant", check="device_code_flow_available",
            title="Device code flow endpoint is published",
            target=domain, severity=Severity.LOW, confidence=Confidence.HIGH,
            description="Device code authorization endpoint is exposed. Useful for device-code phishing chains.",
            data={"endpoint": oidc.get("device_authorization_endpoint")},
            tags=[ChainTag.DEVICE_CODE_FLOW],
            recommendation="Restrict the device-code grant in Conditional Access (block apps via filter on `authentication_methods`) for users who never need it.",
        ))

    # ---- 2. UserRealm + custom domain enumeration ----
    realm = await get_userrealm(http, f"any@{domain}")
    if realm:
        snap.federation_type = realm.get("NameSpaceType", "Unknown")
        snap.tenant_default_name = realm.get("CloudInstanceName", "") or snap.tenant_default_name
        if realm.get("DomainName"):
            snap.primary_domain = realm["DomainName"]
        if realm.get("AuthURL"):
            snap.auth_url = realm["AuthURL"]
        if realm.get("FederationBrandName"):
            snap.branding["federation_brand"] = realm["FederationBrandName"]
        findings.append(data(
            phase="tenant", check="user_realm",
            title=f"User realm: {realm.get('NameSpaceType', '?')}",
            target=domain, confidence=Confidence.HIGH,
            payload={
                "raw": realm,
                "namespace_type": realm.get("NameSpaceType"),
                "federation_brand": realm.get("FederationBrandName"),
                "domain_name": realm.get("DomainName"),
                "cloud_instance": realm.get("CloudInstanceName"),
                "auth_url": realm.get("AuthURL"),
            },
        ))

    # v2.1 user-realm — chases custom domains under same tenant
    realm_v21 = await get_userrealm_v21(http, f"any@{domain}")
    if realm_v21:
        domains = realm_v21.get("federation_protocol", "") or ""
        # Save raw
        om.save_raw(f"tenant/userrealm_v21_{domain}.json", str(realm_v21))
        snap.custom_domains.append({"domain": domain, "type": realm_v21.get("account_type", "")})

    # ---- 3. Branded login page (assets for phishing-prep recon) ----
    if tenant_id:
        html = await get_login_branding(http, tenant_id)
        if html:
            ev_path = om.save_raw(f"tenant/login_branding_{tenant_id}.html", html)
            branding = _extract_branding(html)
            if branding:
                snap.branding.update(branding)
                findings.append(lead(
                    phase="tenant", check="branded_login_page",
                    title=f"Tenant has custom login branding: {branding.get('company_name', 'unknown')}",
                    target=f"https://login.microsoftonline.com/{tenant_id}/...",
                    severity=Severity.LOW, confidence=Confidence.HIGH,
                    description="Custom branding (logo, background, text) detected. Useful for phishing-page cloning recon.",
                    data=branding,
                    tags=[ChainTag.TENANT_BRANDING_LEAKED],
                    recommendation="This is normal; document it as part of the phishing-mitigation plan (visual indicators users see).",
                ))
            else:
                findings.append(validation(
                    phase="tenant", check="default_login_page",
                    title="Login page uses default Microsoft branding",
                    target=domain,
                    payload={"raw_path": str(ev_path)},
                ))

    # ---- 4. Tenant default .onmicrosoft.com discovery ----
    # Confirm via OIDC against {candidate}.onmicrosoft.com — that endpoint will
    # return the SAME tenant_id only for the correct default name.
    if tenant_id:
        # Build candidates: brand from branding, brand from primary domain, common acronyms.
        brand_candidates: list[str] = []
        brand_str = snap.branding.get("federation_brand", "")
        if brand_str:
            cleaned = brand_str.lower().replace(" ", "").replace(".", "").replace(",", "").replace("&", "and")
            brand_candidates.append(cleaned)
        # From primary domain
        if snap.primary_domain:
            brand_candidates.append(snap.primary_domain.split(".")[0])
        # Dedupe + filter
        seen_b: set[str] = set()
        for cand in brand_candidates:
            if not cand or cand in seen_b:
                continue
            seen_b.add(cand)
            test_oidc, _ = await get_oidc_config(http, f"{cand}.onmicrosoft.com")
            if not test_oidc:
                continue
            test_issuer = test_oidc.get("issuer", "")
            mt = GUID_RE.search(test_issuer)
            if mt and mt.group(0).lower() == tenant_id:
                snap.tenant_default_name = f"{cand}.onmicrosoft.com"
                findings.append(data(
                    phase="tenant", check="tenant_default_confirmed",
                    title=f"Tenant default name confirmed: {snap.tenant_default_name}",
                    target=domain, confidence=Confidence.CONFIRMED,
                    payload={"default": snap.tenant_default_name, "via_oidc": True},
                ))
                break
        else:
            # No confirmed default — leave None and emit a low-confidence guess if we have one
            if brand_candidates:
                snap.tenant_default_name = f"{brand_candidates[0]}.onmicrosoft.com"
                findings.append(data(
                    phase="tenant", check="tenant_default_guess",
                    title=f"Tenant default name (unconfirmed guess): {snap.tenant_default_name}",
                    target=domain, confidence=Confidence.LOW,
                    payload={"default": snap.tenant_default_name, "via_oidc": False},
                ))

    return findings
