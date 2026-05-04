"""Phase 9 — Tenant linkage / sibling tenant discovery."""
from __future__ import annotations

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


async def get_tenant_id_for_domain(http: StealthClient, domain: str) -> str | None:
    """Resolve tenant ID for an arbitrary domain via OIDC discovery."""
    url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
    r = await http.get(url)
    if not r or r.status_code >= 400:
        return None
    try:
        j = r.json()
        issuer = j.get("issuer", "")
        # issuer = https://sts.windows.net/{tenant_id}/
        parts = issuer.rstrip("/").split("/")
        if parts:
            return parts[-1].lower()
    except Exception:  # noqa: BLE001
        return None
    return None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    if not snap.tenant_id:
        return findings

    # Heuristic: try common brand-name TLD permutations of the apex
    apex = (snap.primary_domain or ctx.target).lower()
    parts = apex.split(".")
    if len(parts) < 2:
        return findings

    brand = parts[0]
    tlds = ["com", "net", "co.uk", "co.il", "io", "app", "ai", "cloud", "tech", "dev"]
    candidates = [f"{brand}.{tld}" for tld in tlds if f"{brand}.{tld}" != apex]

    sibling_hits: list[dict] = []
    for cand in candidates[:20]:
        tid = await get_tenant_id_for_domain(http, cand)
        if tid and tid == snap.tenant_id:
            sibling_hits.append({"domain": cand, "tenant_id": tid, "shared_with": apex})

    if sibling_hits:
        findings.append(lead(
            phase="tenant_linkage", check="sibling_domains_same_tenant",
            title=f"Found {len(sibling_hits)} sibling domains in the same tenant",
            target=ctx.target, severity=Severity.LOW, confidence=Confidence.HIGH,
            description="Domains under the same tenant share AD/identity surface. Useful for M&A leakage detection, multi-brand recon, and broader phishing surfaces.",
            data={"siblings": sibling_hits, "tenant_id": snap.tenant_id},
            tags=[ChainTag.TENANT_DOMAINS_ENUMERATED],
            recommendation="Inventory all federated/managed domains in this tenant; ensure consistent CA policy across them.",
        ))
        for h in sibling_hits:
            findings.append(data(
                phase="tenant_linkage", check="sibling_domain",
                title=f"Sibling: {h['domain']}",
                target=h["domain"], confidence=Confidence.HIGH,
                payload=h,
            ))

    return findings
