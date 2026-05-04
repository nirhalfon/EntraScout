"""Phase 37 — HTTP security-header roll-up across key org endpoints.

Audits HSTS, CSP, X-Frame-Options, COOP, COEP, Referrer-Policy,
Permissions-Policy, Strict-Transport-Security across the apex + key
discovered subdomains. Each missing header on a public endpoint is an
audit-flag.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", Severity.MEDIUM),
    ("content-security-policy", "CSP", Severity.LOW),
    ("x-frame-options", "X-Frame-Options", Severity.LOW),
    ("x-content-type-options", "X-Content-Type-Options", Severity.LOW),
    ("referrer-policy", "Referrer-Policy", Severity.LOW),
    ("permissions-policy", "Permissions-Policy", Severity.LOW),
    ("cross-origin-opener-policy", "COOP", Severity.LOW),
    ("cross-origin-embedder-policy", "COEP", Severity.LOW),
    ("cross-origin-resource-policy", "CORP", Severity.LOW),
]

LEAK_HEADERS = [
    ("server", "Server"),
    ("x-powered-by", "X-Powered-By"),
    ("x-aspnet-version", "X-AspNet-Version"),
    ("x-aspnetmvc-version", "X-AspNetMvc-Version"),
    ("x-generator", "X-Generator"),
    ("via", "Via"),
]


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()

    targets: set[str] = {f"https://{apex}", f"https://www.{apex}"}
    for f in om.findings:
        t = (f.target or "")
        if t.startswith("https://") and apex in t.split("/")[2]:
            host = t.split("/")[2]
            targets.add(f"https://{host}")
    targets_list = list(targets)[:8]

    sem = asyncio.Semaphore(min(ctx.workers, 6))

    async def probe(url: str) -> None:
        async with sem:
            r = await http.get(url)
        if not r:
            return
        h = {k.lower(): v for k, v in (r.headers or {}).items()}
        missing = [(name, label, sev) for hdr, label, sev in SECURITY_HEADERS
                   for name in [hdr] if hdr not in h]
        leaks = [(label, h[hdr]) for hdr, label in LEAK_HEADERS if hdr in h]

        # Single roll-up finding per host
        findings.append(data(
            phase="http_headers", check="security_headers_audit",
            title=f"Security-header audit: {url} — {len(missing)} missing, {len(leaks)} info leaks",
            target=url, confidence=Confidence.HIGH,
            payload={
                "url": url,
                "status": r.status_code,
                "missing_security_headers": [m[1] for m in missing],
                "info_disclosure_headers": dict(leaks),
                "recommendation": "Add missing security headers; strip Server / X-Powered-By to reduce fingerprint surface.",
            },
        ))

        # If HSTS specifically is missing on an HTTPS endpoint, that's a real finding
        if "strict-transport-security" not in h:
            findings.append(lead(
                phase="http_headers", check="hsts_missing",
                title=f"HSTS not set on {url}",
                target=url, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description="HTTP Strict-Transport-Security header missing — clients can be downgraded to HTTP.",
                data={"url": url},
                recommendation="Set: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            ))

    await asyncio.gather(*(probe(u) for u in targets_list))

    return findings
