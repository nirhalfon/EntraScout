"""Phase 4 — Microsoft 365 service exposure (SharePoint, OneDrive, Exchange, Teams, etc.)."""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from ..dns_client import query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, is_existence_signal, lead, validation


# Hosts that are MS shared infrastructure (every M365 customer "has" them).
# We probe them ONCE per phase rather than per-tenant-host candidate.
SHARED_EXCHANGE_HOSTS = ("outlook.office365.com",)


async def head_or_get(http: StealthClient, url: str) -> tuple[int | None, dict, str]:
    r = await http.head(url)
    if not r:
        r = await http.get(url)
    if not r:
        return None, {}, ""
    return r.status_code, dict(r.headers), r.text[:500]


async def get_autodiscover_v2(http: StealthClient, login: str, protocol: str = "AutodiscoverV1") -> dict | None:
    url = f"https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{login}?Protocol={protocol}"
    r = await http.get(url, headers={"Accept": "application/json"})
    if not r:
        return None
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return {"raw": r.text[:300], "status": r.status_code}


async def teams_federation(http: StealthClient, domain: str) -> str | None:
    """getfederationinformation SOAP call. Returns body or None."""
    url = f"https://webdir.online.lync.com/AutoDiscover/AutoDiscoverservice.svc/root/domain/{domain}"
    r = await http.get(url, headers={"Accept": "application/json"})
    if r and r.status_code in (200, 400, 404):
        return r.text[:1000]
    return None


SHAREPOINT_TENANT_PATTERNS = [
    ("SVC_SHAREPOINT", "https://{tenant}.sharepoint.com", "SharePoint Online"),
    ("SVC_ONEDRIVE", "https://{tenant}-my.sharepoint.com", "OneDrive for Business"),
    ("SVC_SP_ADMIN", "https://{tenant}-admin.sharepoint.com", "SharePoint admin center"),
]

EXCHANGE_PATHS = [
    ("OWA", "/owa/", ChainTag.SVC_OWA),
    ("ECP", "/ecp/", ChainTag.SVC_ECP),
    ("EWS", "/EWS/Exchange.asmx", ChainTag.SVC_EWS),
    ("ActiveSync", "/Microsoft-Server-ActiveSync", ChainTag.SVC_ACTIVESYNC),
    ("MAPI", "/mapi/emsmdb", None),
    ("OAB", "/OAB/", None),
    ("Autodiscover", "/autodiscover/autodiscover.xml", None),
]


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    domain = snap.primary_domain or ctx.target
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "")

    sem = asyncio.Semaphore(ctx.workers)

    # ---- SharePoint / OneDrive / Admin ----
    if tenant_short:
        for tag_name, pattern, label in SHAREPOINT_TENANT_PATTERNS:
            url = pattern.format(tenant=tenant_short)
            async with sem:
                code, headers, body_snip = await head_or_get(http, url)
            if code and is_existence_signal(code):
                tag_map = {
                    "SVC_SHAREPOINT": ChainTag.SVC_SHAREPOINT,
                    "SVC_ONEDRIVE": ChainTag.SVC_ONEDRIVE,
                }
                tags = [tag_map[tag_name]] if tag_name in tag_map else []
                findings.append(data(
                    phase="m365_services", check=f"sharepoint_{tag_name.lower()}",
                    title=f"{label} present at {urlparse(url).hostname}",
                    target=url, confidence=Confidence.CONFIRMED,
                    payload={"service": label, "url": url, "status": code,
                             "server": headers.get("server", ""), "x-sp-version": headers.get("microsoftsharepointteamservices", "")},
                    tags=tags,
                ))

    # ---- Exchange Online surface ----
    # 1) Probe the SHARED MS host once (dedupe noise).
    # 2) Only also probe tenant-customized hosts (webmail.<domain>, mail.<domain>) if DNS resolves.
    exchange_hosts: list[str] = list(SHARED_EXCHANGE_HOSTS)
    for prefix in ("webmail", "mail", "outlook"):
        candidate = f"{prefix}.{domain}"
        # DNS-resolve first so we don't blast 6+ paths at NXDOMAIN
        recs = await query(candidate, "A") or await query(candidate, "CNAME")
        if recs:
            exchange_hosts.append(candidate)

    for host in exchange_hosts:
        for label, path, tag in EXCHANGE_PATHS:
            url = f"https://{host}{path}"
            async with sem:
                code, headers, body_snip = await head_or_get(http, url)
            if code and is_existence_signal(code):
                # Shared MS hosts are downgraded to validation (every M365 customer has them).
                is_shared = host in SHARED_EXCHANGE_HOSTS
                if is_shared:
                    findings.append(validation(
                        phase="m365_services", check=f"exchange_{label.lower()}_shared",
                        title=f"Exchange Online {label} confirmed (shared MS host)",
                        target=url,
                        payload={
                            "service": f"Exchange-{label}", "url": url, "status": code,
                            "server": headers.get("server", ""),
                            "owa_version": headers.get("x-owa-version", ""),
                            "shared_host": True,
                        },
                        tags=[tag, ChainTag.SVC_EXCHANGE] if tag else [ChainTag.SVC_EXCHANGE],
                    ))
                else:
                    findings.append(data(
                        phase="m365_services", check=f"exchange_{label.lower()}",
                        title=f"Exchange {label} reachable on tenant host: {url}",
                        target=url, confidence=Confidence.HIGH,
                        payload={
                            "service": f"Exchange-{label}", "url": url, "status": code,
                            "server": headers.get("server", ""),
                            "owa_version": headers.get("x-owa-version", ""),
                            "tenant_customized_host": True,
                        },
                        tags=[tag, ChainTag.SVC_EXCHANGE] if tag else [ChainTag.SVC_EXCHANGE],
                    ))

    # ---- Autodiscover v2 (rich tenant info) ----
    if domain:
        ad = await get_autodiscover_v2(http, f"any@{domain}")
        if ad:
            om.save_raw(f"m365_services/autodiscover_v2_{domain}.json", str(ad))
            findings.append(data(
                phase="m365_services", check="autodiscover_v2",
                title="Autodiscover v2 returned tenant routing info",
                target=domain, confidence=Confidence.HIGH,
                payload={"raw": ad},
                tags=[ChainTag.SVC_EXCHANGE],
            ))

    # ---- Teams / Lync federation ----
    fed = await teams_federation(http, domain)
    if fed:
        om.save_raw(f"m365_services/teams_federation_{domain}.txt", fed)
        findings.append(data(
            phase="m365_services", check="teams_federation",
            title="Teams/Lync federation discovery responded",
            target=domain, confidence=Confidence.MEDIUM,
            payload={"raw_excerpt": fed[:800]},
            tags=[ChainTag.SVC_TEAMS, ChainTag.SVC_LYNCDISCOVER],
        ))

    # ---- Lync discover ----
    for url in (f"https://lyncdiscover.{domain}/", f"https://meet.lync.com/{domain}"):
        async with sem:
            code, headers, _ = await head_or_get(http, url)
        if code and is_existence_signal(code):
            findings.append(data(
                phase="m365_services", check="lyncdiscover",
                title=f"Skype/Teams legacy discovery: {url}",
                target=url, confidence=Confidence.HIGH,
                payload={"service": "Lyncdiscover", "url": url, "status": code},
                tags=[ChainTag.SVC_LYNCDISCOVER],
            ))
            break

    # ---- Yammer / Viva Engage ----
    yammer_url = f"https://www.yammer.com/{domain}"
    code, _, _ = await head_or_get(http, yammer_url)
    if code and code != 404:
        findings.append(data(
            phase="m365_services", check="yammer",
            title=f"Yammer / Viva Engage tenant exists at {yammer_url}",
            target=yammer_url, confidence=Confidence.MEDIUM,
            payload={"service": "Yammer/VivaEngage", "url": yammer_url, "status": code},
            tags=[ChainTag.SVC_YAMMER],
        ))

    # ---- SharePoint verification files (BingSiteAuth.xml etc.) ----
    if tenant_short:
        for vfile in ("BingSiteAuth.xml", "Microsoft365.xml", "MicrosoftSitelock.xml"):
            url = f"https://{tenant_short}.sharepoint.com/{vfile}"
            code, headers, body = await head_or_get(http, url)
            if code == 200 and body:
                findings.append(data(
                    phase="m365_services", check=f"sp_verification_{vfile.lower().replace('.', '_')}",
                    title=f"SharePoint verification file exposed: /{vfile}",
                    target=url, confidence=Confidence.HIGH,
                    payload={"service": "SharePoint", "url": url, "status": code, "body_excerpt": body[:300]},
                    tags=[ChainTag.SVC_SHAREPOINT],
                ))

    return findings
