"""Phase 36 — Subdomain takeover hunter (Microsoft-specific patterns).

For each subdomain we've discovered (from sibling_domains, MX, CNAME chains
in prior findings) check whether it CNAMEs to a deletable Azure-managed
hostname. If the target Azure resource name returns a fingerprint matching
the "claimable" state (typically NXDOMAIN on the target service or a 404
with a known error string), flag as TAKEOVER CANDIDATE.
"""
from __future__ import annotations

import asyncio

from ..dns_client import query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, issue, lead


# Patterns: (cname_suffix, fingerprint_in_response_body_or_status, service_label)
TKO_PATTERNS = [
    (".cloudapp.net",
     None,
     "Azure Cloud Service (legacy) — NXDOMAIN means service deleted, claimable"),
    (".cloudapp.azure.com",
     None,
     "Azure Cloud Service (newer) — NXDOMAIN means deletable"),
    (".azurewebsites.net",
     "404 Web Site - 404 Web Site not found",
     "Azure App Service — 404 with this fingerprint = name available for re-registration"),
    (".trafficmanager.net",
     None,
     "Azure Traffic Manager — NXDOMAIN means profile deleted, name claimable"),
    (".azurefd.net",
     None,
     "Azure Front Door (legacy AFD classic) — NXDOMAIN means profile deletable"),
    (".azurestaticapps.net",
     "404 Not Found",
     "Azure Static Web App — 404 means swa deleted"),
    (".blob.core.windows.net",
     "BlobNotFound",
     "Azure Blob Storage — name available if storage account is deleted"),
    (".file.core.windows.net",
     None,
     "Azure File Service — same namespace as blob, claimable"),
    (".search.windows.net",
     None,
     "Azure Cognitive Search — name claimable if service deleted"),
    (".azurecontainer.io",
     None,
     "Azure Container Instance (legacy) — name claimable"),
    (".azure-api.net",
     None,
     "Azure API Management — name claimable if APIM service deleted"),
]


async def get_cnames(name: str, depth: int = 3) -> list[str]:
    """Follow CNAME chain. Returns list of CNAME targets (depth-bounded)."""
    out: list[str] = []
    current = name
    for _ in range(depth):
        try:
            res = await query(current, "CNAME", timeout=5.0)
        except Exception:
            break
        if not res:
            break
        target = res[0].rstrip(".").lower()
        out.append(target)
        if target == current:
            break
        current = target
    return out


async def probe_a(name: str) -> bool:
    try:
        res = await query(name, "A", timeout=5.0)
        return bool(res)
    except Exception:
        return False


async def probe_http(http: StealthClient, host: str) -> tuple[int | None, str]:
    url = f"https://{host}"
    r = await http.get(url)
    if not r:
        return None, ""
    body = (r.text or "")[:500] if hasattr(r, "text") else ""
    return r.status_code, body


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()

    # Discover candidate subdomains: any host referenced in prior findings + apex
    candidates: set[str] = {apex, f"www.{apex}", f"login.{apex}", f"app.{apex}"}
    for f in om.findings:
        target = (f.target or "").lower()
        if "://" in target:
            host = target.split("://", 1)[1].split("/")[0].split(":")[0]
        else:
            host = target.split("/")[0].split(":")[0]
        if host and "." in host and host.endswith(("." + apex, apex)) and host not in candidates:
            candidates.add(host)

    # Cap to avoid runaway
    candidates_list = list(candidates)[:50]

    sem = asyncio.Semaphore(min(ctx.workers, 6))

    async def check_tko(name: str) -> None:
        async with sem:
            cnames = await get_cnames(name)
        if not cnames:
            return
        # Look for a known TKO suffix in the chain
        for tgt in cnames:
            for suffix, fingerprint, label in TKO_PATTERNS:
                if not tgt.endswith(suffix):
                    continue
                # Probe the target to see if it resolves
                async with sem:
                    has_a = await probe_a(tgt)
                if not has_a:
                    # NXDOMAIN on target = takeover-class for services that don't pre-reserve names
                    findings.append(issue(
                        phase="subdomain_takeover", check="cname_to_dangling_azure",
                        title=f"Subdomain takeover candidate: {name} → {tgt} (NXDOMAIN)",
                        target=name, severity=Severity.HIGH, confidence=Confidence.HIGH,
                        description=(
                            f"DNS chain `{name} → ... → {tgt}` ends at an Azure-managed "
                            f"hostname that does NOT resolve. {label}"
                        ),
                        data={"name": name, "cname_chain": cnames, "dangling_target": tgt,
                              "service_pattern": suffix, "service_label": label},
                        tags=[ChainTag.AZ_BLOB if "blob" in suffix else ChainTag.AZ_APPSERVICE if "azurewebsites" in suffix else ChainTag.AZ_FRONT_DOOR],
                        recommendation=(
                            f"Either re-create the Azure resource at `{tgt}` (under tenant "
                            f"control, blocks attacker re-registration) or remove the "
                            f"DNS record `{name}`."
                        ),
                    ))
                else:
                    # Target resolves — probe HTTP for fingerprint
                    if fingerprint:
                        async with sem:
                            code, body = await probe_http(http, tgt)
                        if code == 404 and fingerprint in body:
                            findings.append(issue(
                                phase="subdomain_takeover", check="cname_to_404_fingerprint",
                                title=f"Subdomain takeover candidate (404 fingerprint): {name} → {tgt}",
                                target=name, severity=Severity.HIGH, confidence=Confidence.HIGH,
                                description=(
                                    f"DNS resolves but the Azure resource at `{tgt}` returns "
                                    f"a 404 with the fingerprint `{fingerprint}` — this means "
                                    f"the resource was deleted but the name is still claimable."
                                ),
                                data={"name": name, "cname_chain": cnames, "target": tgt,
                                      "status": code, "fingerprint": fingerprint, "service_label": label},
                                recommendation="Re-register the Azure resource OR remove the DNS record.",
                            ))
                break  # only flag once per pattern match

    await asyncio.gather(*(check_tko(c) for c in candidates_list))

    return findings
