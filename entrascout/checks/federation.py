"""Phase 2 — Federation deep-dive (ADFS, IdPs, AAD Connect, Seamless SSO)."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, issue, lead, validation


THIRD_PARTY_IDP_HINTS = {
    "okta.com": "Okta",
    "oktapreview.com": "Okta",
    "ping.com": "Ping Identity",
    "pingidentity.com": "Ping Identity",
    "pingone.com": "Ping Identity",
    "onelogin.com": "OneLogin",
    "auth0.com": "Auth0",
    "duosecurity.com": "Duo (Cisco)",
    "jumpcloud.com": "JumpCloud",
    "centrify.com": "Centrify (Delinea)",
    "delinea.com": "Delinea",
    "cyberark.com": "CyberArk",
    "google.com": "Google as IdP",
    "googleapis.com": "Google as IdP",
    "secureauth.com": "SecureAuth",
    "rsa.com": "RSA",
    "miniorange.com": "miniOrange",
}


async def get_adfs_oidc(http: StealthClient, host: str) -> dict | None:
    url = f"https://{host}/adfs/.well-known/openid-configuration"
    r = await http.get(url)
    if not r or r.status_code >= 400:
        return None
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return None


async def get_adfs_mex(http: StealthClient, host: str) -> str | None:
    url = f"https://{host}/adfs/services/trust/mex"
    r = await http.get(url)
    if not r or r.status_code >= 400:
        return None
    return r.text


async def get_federation_metadata(http: StealthClient, host: str) -> str | None:
    url = f"https://{host}/FederationMetadata/2007-06/FederationMetadata.xml"
    r = await http.get(url)
    if not r or r.status_code >= 400:
        return None
    return r.text


# Suspicious / red-flag tokens in Relying Party names that warrant elevated severity.
RP_SENSITIVE_TOKENS = {
    "admin": "admin portal",
    "claimsxray": "Microsoft debug Relying Party (should never be in production)",
    "test": "non-production environment registered alongside prod",
    "dev": "development environment",
    "stage": "staging environment",
    "ops]": "operations admin (e.g. [Ops] prefix)",
    "knox": "Samsung Knox / privileged management",
    "sso": "SSO admin",
    "idp": "IdP admin",
    "vault": "secrets vault",
    "sap": "SAP",
    "workday": "Workday HR",
    "salesforce": "Salesforce",
    "zscaler": "Zscaler admin",
    "privileg": "privileged access",
    "secret": "secrets",
    "sti(": "Threat Intelligence (named explicitly)",
}


async def get_idp_initiated_signon(http: StealthClient, host: str) -> str | None:
    """Fetch the ADFS IdP-Initiated Signon page. Microsoft hardening guide
    recommends disabling this — its presence + RP catalog disclosure is a
    high-impact finding on its own."""
    url = f"https://{host}/adfs/ls/idpinitiatedsignon.aspx"
    r = await http.get(url)
    if not r or r.status_code != 200:
        return None
    return r.text


def parse_relying_parties(html: str) -> list[str]:
    """Extract <option>RP-name</option> values from the IdP-initiated signon page."""
    matches = re.findall(r'<option value="[^"]+">([^<]+)</option>', html)
    return [m.strip() for m in matches if m.strip()]


def classify_relying_parties(rps: list[str]) -> dict[str, list[tuple[str, str]]]:
    """Group RPs by sensitivity tokens. Returns {token_label: [(rp, reason), ...]}."""
    by_token: dict[str, list[tuple[str, str]]] = {}
    for rp in rps:
        rp_low = rp.lower()
        for tok, label in RP_SENSITIVE_TOKENS.items():
            if tok in rp_low:
                by_token.setdefault(label, []).append((rp, label))
                break
    return by_token


async def check_seamless_sso(http: StealthClient, domain: str) -> bool:
    url = f"https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/usernamemixed"
    r = await http.post(url, data="<garbage>", headers={"Content-Type": "application/soap+xml"})
    # Endpoint exists if we get any response at all (typically 400 from bad payload, but exists)
    return r is not None


def detect_idp(auth_url: str) -> tuple[str | None, str | None]:
    """Detect 3rd-party IdP from the AuthURL."""
    if not auth_url:
        return None, None
    host = urlparse(auth_url).hostname or ""
    for hint, name in THIRD_PARTY_IDP_HINTS.items():
        if hint in host:
            return name, host
    if "adfs" in host.lower() or "/adfs/" in auth_url.lower():
        return "ADFS (on-prem)", host
    return None, host


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []

    # We expect snap.federation_type / snap.auth_url to be populated by tenant.py
    ftype = (snap.federation_type or "").lower()
    auth_url = snap.auth_url or ""

    if "managed" in ftype:
        findings.append(validation(
            phase="federation", check="managed_tenant",
            title="Tenant uses cloud-only (Managed) authentication",
            target=ctx.target,
            payload={"namespace_type": snap.federation_type},
            tags=[ChainTag.FED_MANAGED],
        ))
    elif "federated" in ftype:
        idp_name, idp_host = detect_idp(auth_url)
        snap.federated_idp = idp_name or "Unknown federated IdP"

        # ADFS path
        if idp_name and "ADFS" in idp_name:
            findings.append(lead(
                phase="federation", check="adfs_detected",
                title=f"On-prem ADFS detected at {idp_host}",
                target=idp_host or "", severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description="Tenant authenticates via on-prem ADFS. ADFS is a high-value target — token-signing certificate exfil leads to Golden SAML.",
                data={"adfs_host": idp_host, "auth_url": auth_url},
                tags=[ChainTag.FED_FEDERATED, ChainTag.FED_ADFS_DETECTED],
                recommendation="Audit ADFS for: latest CU patch level, MEX endpoint exposure (`/adfs/services/trust/mex`), token-signing cert rotation, ESA, and modern auth posture. Consider migrating to Pass-Through Authentication (PTA) to reduce attack surface.",
            ))

            # Probe ADFS MEX (token-signing cert exfil surface)
            if idp_host:
                mex = await get_adfs_mex(http, idp_host)
                if mex and "<wsdl:" in mex.lower():
                    om.save_raw(f"federation/adfs_mex_{idp_host}.xml", mex)
                    findings.append(issue(
                        phase="federation", check="adfs_mex_exposed",
                        title=f"ADFS MEX endpoint publicly accessible at {idp_host}",
                        target=f"https://{idp_host}/adfs/services/trust/mex",
                        severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                        description="ADFS Metadata Exchange is reachable unauthenticated. Token-signing certificate is referenced here. With on-prem ADFS access, this enables Golden SAML.",
                        data={"adfs_host": idp_host},
                        tags=[ChainTag.FED_ADFS_MEX_EXPOSED],
                        recommendation="Restrict /adfs/services/trust/mex to internal networks only. Place ADFS proxy (Web Application Proxy) inline and limit external mex exposure. See Microsoft KB on hardening ADFS.",
                    ))

                # ADFS OIDC (version fingerprint)
                adfs_oidc = await get_adfs_oidc(http, idp_host)
                if adfs_oidc:
                    findings.append(data(
                        phase="federation", check="adfs_oidc",
                        title=f"ADFS OIDC config at {idp_host}",
                        target=idp_host, confidence=Confidence.HIGH,
                        payload={
                            "issuer": adfs_oidc.get("issuer"),
                            "endpoints": {
                                "auth": adfs_oidc.get("authorization_endpoint"),
                                "token": adfs_oidc.get("token_endpoint"),
                                "userinfo": adfs_oidc.get("userinfo_endpoint"),
                                "jwks": adfs_oidc.get("jwks_uri"),
                            },
                            "scopes_supported": adfs_oidc.get("scopes_supported"),
                            "response_types": adfs_oidc.get("response_types_supported"),
                        },
                    ))

                # FederationMetadata XML (older route, leaks more)
                fed_meta = await get_federation_metadata(http, idp_host)
                if fed_meta and "<EntityDescriptor" in fed_meta:
                    om.save_raw(f"federation/fedmeta_{idp_host}.xml", fed_meta)
                    findings.append(lead(
                        phase="federation", check="adfs_federation_metadata",
                        title=f"ADFS FederationMetadata.xml exposed at {idp_host}",
                        target=f"https://{idp_host}/FederationMetadata/2007-06/FederationMetadata.xml",
                        severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                        description="FederationMetadata.xml exposes ADFS roles, endpoints, and certs - useful for fingerprinting and Golden SAML prep.",
                        recommendation="Restrict FederationMetadata.xml to authenticated intranet access only.",
                    ))

                # IdP-Initiated Signon page + Relying Party catalog enumeration
                # Microsoft hardening guidance recommends disabling this; its presence
                # is itself a finding, AND the page leaks the full RP catalog.
                signon_html = await get_idp_initiated_signon(http, idp_host)
                if signon_html:
                    om.save_raw(f"federation/idpinitiatedsignon_{idp_host}.html", signon_html)
                    findings.append(issue(
                        phase="federation", check="adfs_idpinitiatedsignon_enabled",
                        title=f"ADFS IdP-Initiated Signon page enabled at {idp_host}",
                        target=f"https://{idp_host}/adfs/ls/idpinitiatedsignon.aspx",
                        severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                        description=(
                            "Microsoft hardening guidance recommends disabling idpinitiatedsignon.aspx "
                            "(Set-AdfsProperties -EnableIdpInitiatedSignonPage $false). Its presence "
                            "creates a phishing primitive: attacker-supplied links land victims on a "
                            "real organization-branded login form on a real organization-owned URL."
                        ),
                        data={"adfs_host": idp_host},
                        recommendation=(
                            "Run `Set-AdfsProperties -EnableIdpInitiatedSignonPage $false` on the ADFS server. "
                            "After the change, idpinitiatedsignon.aspx returns 404. See Microsoft Learn: "
                            "https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-and-azure-mfa"
                        ),
                    ))

                    # Parse + classify the leaked Relying Parties
                    rps = parse_relying_parties(signon_html)
                    if rps:
                        # Severity scaled by RP count
                        if len(rps) >= 100:
                            sev = Severity.HIGH
                        elif len(rps) >= 10:
                            sev = Severity.MEDIUM
                        else:
                            sev = Severity.LOW
                        classified = classify_relying_parties(rps)
                        sample = rps[:50]
                        findings.append(issue(
                            phase="federation", check="adfs_relying_party_catalog_disclosed",
                            title=f"ADFS Relying Party catalog leaked at {idp_host} ({len(rps)} RPs)",
                            target=f"https://{idp_host}/adfs/ls/idpinitiatedsignon.aspx",
                            severity=sev, confidence=Confidence.CONFIRMED,
                            description=(
                                f"The IdP-Initiated Signon page exposes {len(rps)} registered Relying Party "
                                f"names anonymously. This catalogs internal applications, vendor relationships, "
                                f"and (often) admin / test / debug Relying Parties by name. Used by attackers "
                                f"for targeted phishing, supply-chain prioritization, and RP-impersonation."
                            ),
                            data={
                                "adfs_host": idp_host,
                                "rp_count": len(rps),
                                "sample_rps": sample,
                                "sensitive_classified": {
                                    label: [rp for rp, _ in items[:10]]
                                    for label, items in classified.items()
                                },
                            },
                            recommendation=(
                                "Disable idpinitiatedsignon.aspx as above. Audit all Relying Parties for "
                                "stale, test, or debug registrations (especially `ClaimsXray` - Microsoft's "
                                "debug RP that should never exist in production)."
                            ),
                        ))
                        # If we found ClaimsXray specifically, surface a separate HIGH issue
                        for rp in rps:
                            if "claimsxray" in rp.lower():
                                findings.append(issue(
                                    phase="federation", check="adfs_claimsxray_in_production",
                                    title=f"ADFS production environment has Microsoft debug Relying Party `ClaimsXray` registered",
                                    target=f"https://{idp_host}/adfs/ls/idpinitiatedsignon.aspx",
                                    severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                                    description=(
                                        "ClaimsXray is a Microsoft-published debug Relying Party from "
                                        "adfshelp.microsoft.com used to inspect ADFS-issued claims and "
                                        "test claim rules. It accepts arbitrary claims and should NEVER "
                                        "exist in production. Its presence indicates a configuration-"
                                        "management gap (left over from ADFS commissioning)."
                                    ),
                                    data={"adfs_host": idp_host, "rp_name": rp},
                                    recommendation=(
                                        "On the ADFS server: "
                                        "Remove-AdfsRelyingPartyTrust -TargetName 'ClaimsXray'"
                                    ),
                                ))
                                break

                # ADFS password update endpoint (auxiliary phishing surface)
                pwd_url = f"https://{idp_host}/adfs/portal/updatepassword"
                pr = await http.head(pwd_url)
                if pr and pr.status_code == 200:
                    findings.append(lead(
                        phase="federation", check="adfs_updatepassword_exposed",
                        title=f"ADFS password update endpoint reachable at {idp_host}",
                        target=pwd_url,
                        severity=Severity.LOW, confidence=Confidence.HIGH,
                        description=(
                            "/adfs/portal/updatepassword is anonymously reachable on the public internet. "
                            "Provides credential-stuffing surface with different rate-limit characteristics "
                            "from the regular login flow, plus a phishing landing page on a real "
                            "organization-owned URL ('Your password expired - update now')."
                        ),
                        recommendation=(
                            "Restrict /adfs/portal/updatepassword to internal networks only via "
                            "Web Application Proxy publishing rules."
                        ),
                    ))

        elif idp_name:
            findings.append(lead(
                phase="federation", check="thirdparty_idp",
                title=f"Federated to 3rd-party IdP: {idp_name}",
                target=idp_host or "", severity=Severity.LOW, confidence=Confidence.HIGH,
                description=f"Tenant federates to {idp_name}. Recon the IdP for known CVEs, MFA posture, and IdP-specific attack chains.",
                data={"idp": idp_name, "idp_host": idp_host, "auth_url": auth_url},
                tags=[ChainTag.FED_FEDERATED, ChainTag.FED_THIRDPARTY_IDP],
                recommendation=f"For phishing realism, consider cloning the {idp_name} login page rather than the Microsoft one — that's where credentials are entered.",
            ))
        else:
            findings.append(data(
                phase="federation", check="federated_unknown_idp",
                title="Federated to unknown IdP",
                target=ctx.target, confidence=Confidence.MEDIUM,
                payload={"auth_url": auth_url, "idp_host": idp_host},
                tags=[ChainTag.FED_FEDERATED],
            ))

    # ---- Seamless SSO probe (works on managed tenants) ----
    if "managed" in ftype:
        sso = await check_seamless_sso(http, ctx.target)
        if sso:
            snap.seamless_sso = True
            findings.append(lead(
                phase="federation", check="seamless_sso_enabled",
                title="Seamless SSO endpoint is reachable for the domain",
                target=f"https://autologon.microsoftazuread-sso.com/{ctx.target}/...",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                description="Seamless Single Sign-On is configured. Indicates AD Connect is in use — internal foothold pivots to AAD via the AZUREADSSOACC$ machine account.",
                tags=[ChainTag.FED_SEAMLESS_SSO, ChainTag.FED_AAD_CONNECT_PHS],
                recommendation="Rotate the AZUREADSSOACC$ password regularly (Microsoft recommends every 90 days). Audit who has reset rights on that account.",
            ))

    return findings
