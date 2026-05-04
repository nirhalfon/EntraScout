"""Phase 6 — Authentication attack surface (legacy auth, MFA gaps, lockout) — RECON only."""
from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, issue, lead, validation


LEGACY_HOSTS = {
    "smtp": ("smtp.office365.com", 587, ChainTag.LEGACY_AUTH_SMTP),
    "imap": ("outlook.office365.com", 993, ChainTag.LEGACY_AUTH_IMAP),
    "pop3": ("outlook.office365.com", 995, ChainTag.LEGACY_AUTH_POP),
}


def _tcp_banner(host: str, port: int, timeout: float = 4.0) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if port in (993, 995):  # TLS straight away
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    ss.settimeout(timeout)
                    data = ss.recv(512)
                    return data.decode(errors="replace").strip()
            else:
                s.settimeout(timeout)
                data = s.recv(512)
                if not data:
                    s.sendall(b"EHLO entrascout.local\r\n")
                    data = s.recv(1024)
                return data.decode(errors="replace").strip()
    except Exception:  # noqa: BLE001
        return None


async def probe_legacy(svc: str, host: str, port: int) -> str | None:
    return await asyncio.to_thread(_tcp_banner, host, port)


async def probe_ropc(http: StealthClient, tenant_id: str, client_id: str = "1b730954-1685-4b74-9bfd-dac224a7b894") -> dict | None:
    """Resource-owner password credentials probe — used to fingerprint MFA/CA without actually auth-ing.

    We send invalid creds; the response code tells us about the surface.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    body = {
        "client_id": client_id,
        "scope": "https://graph.microsoft.com/.default",
        "username": "entrascout-probe@example.invalid",
        "password": "EntraScout-NoSuchPwd-2026",
        "grant_type": "password",
    }
    r = await http.post(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    if not r:
        return None
    try:
        return {"status": r.status_code, **r.json()}
    except Exception:  # noqa: BLE001
        return {"status": r.status_code, "raw": r.text[:500]}


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []

    # ---- Legacy auth banner probes ----
    for svc, (host, port, tag) in LEGACY_HOSTS.items():
        banner = await probe_legacy(svc, host, port)
        if banner:
            findings.append(data(
                phase="auth_surface", check=f"legacy_{svc}_banner",
                title=f"{svc.upper()} banner from {host}:{port}",
                target=f"{host}:{port}", confidence=Confidence.HIGH,
                payload={"service": svc, "host": host, "port": port, "banner": banner[:300]},
                tags=[tag],
            ))
        else:
            findings.append(validation(
                phase="auth_surface", check=f"legacy_{svc}_unreachable",
                title=f"{svc.upper()} not reachable on {host}:{port}",
                target=f"{host}:{port}",
                payload={"service": svc, "host": host, "port": port},
            ))

    # ---- ROPC probe to fingerprint CA / MFA / Smart Lockout ----
    if snap.tenant_id:
        ropc = await probe_ropc(http, snap.tenant_id)
        if ropc:
            err = (ropc.get("error_description") or "").lower()
            code = ropc.get("status")
            err_codes = []
            for e in err.split():
                if e.startswith("aadsts"):
                    err_codes.append(e.rstrip(":,."))
            payload = {"status": code, "error": ropc.get("error"), "error_description": ropc.get("error_description"), "aadsts": err_codes}
            om.save_raw(f"auth_surface/ropc_{snap.tenant_id}.json", str(ropc))

            findings.append(data(
                phase="auth_surface", check="ropc_probe",
                title="ROPC probe response captured",
                target=f"login.microsoftonline.com/{snap.tenant_id}/oauth2/v2.0/token",
                confidence=Confidence.HIGH, payload=payload,
                tags=[ChainTag.FOCI_CLIENT_REACHABLE],
            ))

            # Interpret known AADSTS codes
            if "aadsts50034" in err:
                findings.append(data(
                    phase="auth_surface", check="aadsts50034_user_not_found",
                    title="Tenant returns 'AADSTS50034' (user not found) — confirms tenant active",
                    target=ctx.target, confidence=Confidence.HIGH,
                    payload={"signal": "AADSTS50034 — UserAccountNotFound"},
                ))
            if "aadsts50126" in err:
                findings.append(lead(
                    phase="auth_surface", check="legacy_auth_ropc_active",
                    title="Tenant accepts ROPC for the chosen FOCI client (AADSTS50126)",
                    target=ctx.target, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                    description="ROPC is reachable — useful for credential brute force without interactive UI. Indicates legacy auth not fully blocked for this FOCI client.",
                    tags=[ChainTag.MFA_GAP_DETECTED],
                    recommendation="Disable ROPC via Conditional Access (block 'Other clients' / legacy auth). Apply the 'Block legacy authentication' baseline policy.",
                ))
            if "aadsts50053" in err:
                findings.append(data(
                    phase="auth_surface", check="aadsts50053_smart_lockout",
                    title="AADSTS50053 returned — Smart Lockout is engaged",
                    target=ctx.target, confidence=Confidence.HIGH,
                    payload={"signal": "AADSTS50053 — IdsLocked"},
                    tags=[ChainTag.SMART_LOCKOUT_INFERRED],
                ))
            if "aadsts53003" in err:
                findings.append(validation(
                    phase="auth_surface", check="ca_blocks_legacy",
                    title="Conditional Access blocks legacy auth (AADSTS53003)",
                    target=ctx.target,
                    payload={"signal": "AADSTS53003 — CA Block"},
                    tags=[ChainTag.LEGACY_AUTH_BLOCKED],
                ))

    return findings
