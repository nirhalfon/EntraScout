"""Internal-mode probes — extra checks when run from inside the corporate network.

Triggered by `--internal`. Probes for:
- on-prem ADFS (and STS) on common internal hostnames
- on-prem Exchange (Outlook Web App on internal IP)
- AD Connect server presence (DNS hints, port 5985 / 8080)
- internal autodiscover (Exchange on-prem)
- AzureAD Connect Health agent on the on-prem server (TCP probe)
"""
from __future__ import annotations

import asyncio
import socket
from typing import Iterable

from ..dns_client import query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


def _tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001
        return False


async def tcp_open_async(host: str, port: int, timeout: float = 2.0) -> bool:
    return await asyncio.to_thread(_tcp_open, host, port, timeout)


COMMON_INTERNAL_HOSTS_FOR_M365 = [
    # ADFS
    "adfs", "sts", "fs", "auth", "adfs01", "adfs02", "fs01", "sts01",
    # Exchange / IIS
    "owa", "mail", "exch", "exchange", "exchange01", "ex01", "mail01",
    # AAD Connect
    "aadconnect", "azureadconnect", "aadc", "aadc01", "syncsvc",
    # General
    "intranet", "portal", "sharepoint", "sp01", "spwfe",
]


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    if not ctx.mode_internal:
        return findings

    apex = (snap.primary_domain or ctx.target).lower()
    sem = asyncio.Semaphore(ctx.workers)

    # ---- 1. Internal hostname DNS sweep ----
    async def probe_host(name: str) -> None:
        fqdn = f"{name}.{apex}"
        async with sem:
            a = await query(fqdn, "A")
        if not a:
            return
        ip = a[0]
        # Quick TCP fan-out
        ports = {
            443: "HTTPS",
            80: "HTTP",
            3389: "RDP",
            5985: "WinRM-HTTP",
            5986: "WinRM-HTTPS",
            445: "SMB",
            389: "LDAP",
            636: "LDAPS",
            88: "Kerberos",
            8080: "HTTP-alt",
            8443: "HTTPS-alt",
        }
        opens: dict[int, str] = {}
        for port, label in ports.items():
            if await tcp_open_async(ip, port):
                opens[port] = label
        findings.append(data(
            phase="internal_mode", check="internal_host_alive",
            title=f"Internal host responsive: {fqdn} ({ip})",
            target=fqdn, confidence=Confidence.HIGH,
            payload={"fqdn": fqdn, "ip": ip, "open_ports": opens, "name_hint": name},
        ))

        # Heuristic flags
        if name.startswith(("adfs", "sts", "fs", "auth")):
            if 443 in opens:
                # Probe ADFS endpoints from inside
                for path, label in [("/adfs/services/trust/mex", "ADFS MEX (internal)"),
                                    ("/adfs/.well-known/openid-configuration", "ADFS OIDC (internal)"),
                                    ("/adfs/ls/idpinitiatedsignon.aspx", "ADFS IdP-Init Signon (internal)")]:
                    url = f"https://{fqdn}{path}"
                    r = await http.get(url)
                    if r and r.status_code in (200, 401, 403):
                        findings.append(lead(
                            phase="internal_mode", check="adfs_internal_endpoint",
                            title=f"{label}: {url} ({r.status_code})",
                            target=url, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                            description="Internal-facing ADFS endpoint reachable. Combined with on-prem foothold this can lead to Golden SAML.",
                            tags=[ChainTag.FED_ADFS_DETECTED],
                            recommendation="Limit ADFS to required intranet subnets only; protect token-signing cert.",
                        ))
        if name.startswith(("aadconnect", "aadc", "syncsvc")):
            findings.append(lead(
                phase="internal_mode", check="aad_connect_server_candidate",
                title=f"AAD Connect server candidate by name: {fqdn}",
                target=fqdn, severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                description="Hostname suggests AAD Connect / Azure AD Sync service. This server holds privileges to write to Entra and replicate from on-prem AD — a top compromise target.",
                data={"open_ports": opens, "ip": ip},
                tags=[ChainTag.FED_AAD_CONNECT_PHS],
                recommendation="Tier-0 the AAD Connect server: dedicated admin workstation, no internet egress, MFA on local admin, Defender for Identity, regular audits.",
            ))
        if name.startswith(("owa", "mail", "exch", "exchange", "ex0")):
            findings.append(lead(
                phase="internal_mode", check="exchange_onprem_candidate",
                title=f"On-prem Exchange candidate by name: {fqdn}",
                target=fqdn, severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                description="Hostname suggests on-prem Exchange. ProxyShell, ProxyLogon and CVE-2024-21410 etc. are known killers — patch level is critical.",
                data={"open_ports": opens, "ip": ip},
                recommendation="Confirm patch level (ExchangeServer2019 CU# / 2016 CU#). If hybrid, ensure HCW is current and EM is restricted.",
            ))

    await asyncio.gather(*(probe_host(n) for n in COMMON_INTERNAL_HOSTS_FOR_M365))

    return findings
