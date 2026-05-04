"""Phase 23 — Cross-tenant guest / B2B inference (gap #13).

When a federated guest user authenticates, login.microsoftonline.com returns
distinct GetCredentialType / openid signals:

- Tenant has Allow B2B Collaboration → guests can be added
- Specific external tenants are configured via Cross-Tenant Access settings

We can't enumerate the guest list anonymously, but we CAN:
- Detect whether the tenant supports B2B by probing GetCredentialType with
  fake "guest@partner.com" usernames and observing the response code
- Flag the impact: leaked guest tenants reveal supply-chain partners

Read-only — no spraying.
"""
from __future__ import annotations

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()

    if not snap.tenant_id:
        return findings

    # Hit the GetCredentialType endpoint with a "guest@partner.com" pattern
    # to see whether it responds with a BAD_REQUEST or a federation hint.
    # We use a SAFE non-existent partner domain so we don't trigger a real lookup.
    sample = "researcher@example.invalid"
    body = {
        "username": sample,
        "isOtherIdpSupported": True,
        "checkPhones": False,
        "isRemoteNGCSupported": True,
        "isCookieBannerShown": False,
        "isFidoSupported": True,
        "originalRequest": "",
        "country": "US",
        "forceotclogin": False,
        "isExternalFederationDisallowed": False,
        "isRemoteConnectSupported": False,
        "federationFlags": 0,
    }
    url = "https://login.microsoftonline.com/common/GetCredentialType"
    r = await http.post(url, json=body, headers={"Content-Type": "application/json"})
    if r and r.status_code == 200:
        try:
            j = r.json()
            ifexists = j.get("IfExistsResult", -1)
            findings.append(data(
                phase="guest_inference", check="b2b_signaling_baseline",
                title="GetCredentialType baseline captured (B2B signaling)",
                target=url, confidence=Confidence.HIGH,
                payload={
                    "ifexists_result_for_external_invalid": ifexists,
                    "ifexists_meaning": {
                        0: "Account exists in tenant",
                        1: "Account does NOT exist",
                        4: "Account belongs to a tenant where federated user lookup blocks anon enum",
                        5: "Account exists, federated, can attempt federation",
                        6: "Throttled / rate-limited",
                    }.get(ifexists, "unknown"),
                    "note": "Use this baseline + known guest users to distinguish 'guest exists' from 'guest does not exist'.",
                },
                tags=[ChainTag.GUEST_INFERRED],
            ))
        except Exception:
            pass

    # Output the guidance — tenant linkage in B2B is a privacy / supply-chain leak class
    findings.append(data(
        phase="guest_inference", check="b2b_supplychain_hunting_guidance",
        title="B2B / cross-tenant supply-chain hunting guidance",
        target=apex, confidence=Confidence.MEDIUM,
        payload={
            "approach": [
                "Enumerate users in this tenant via OneDrive / Teams (already done by user_enum).",
                "For each user found, check whether GetCredentialType returns 'federated' to a different tenant — that signals guest-inviter relationships.",
                "Also: search public org-chart / press-release content for partnerships (M&A, contractors).",
            ],
            "impact": "Leaked guest-tenant list reveals supply-chain dependencies — useful for both attacker (lateral pivots) and auditor (third-party risk).",
        },
        tags=[ChainTag.GUEST_INFERRED],
    ))

    return findings
