"""Phase 46 — Cross-SaaS tenant existence probes.

Probes whether the org has accounts/tenants on common 3rd-party platforms.
Existence-only; auth-gated portals just confirm tenant presence.

Covered: Atlassian, Slack, Zoom, GitLab, GitHub, Bitbucket, Webex, Notion,
HuggingFace, Cloudflare Pages/Workers, Vercel, Netlify, AWS S3 cross-cloud.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


def variants(brand: str) -> list[str]:
    if not brand or len(brand) < 3:
        return []
    return list(dict.fromkeys([
        brand, f"{brand}-corp", f"{brand}corp", f"{brand}inc", f"{brand}-team",
    ]))


# Each entry is (label, url_template, expected_status_means_exists, severity_hint)
PROBES = [
    ("Atlassian Confluence/Jira tenant",
     "https://{n}.atlassian.net", (200, 301, 302, 401), Severity.LOW),
    ("Slack workspace",
     "https://{n}.slack.com", (200, 301, 302, 404), Severity.LOW),  # 404 still useful: signup is open
    ("Zoom account",
     "https://{n}.zoom.us", (200, 301, 302, 401), Severity.LOW),
    ("Webex tenant",
     "https://{n}.webex.com", (200, 301, 302), Severity.LOW),
    ("Bitbucket workspace",
     "https://bitbucket.org/{n}", (200, 301, 302), Severity.LOW),
    ("GitLab group",
     "https://gitlab.com/{n}", (200,), Severity.LOW),
    ("GitHub org",
     "https://github.com/{n}", (200,), Severity.LOW),
    ("HuggingFace org (AI/ML)",
     "https://huggingface.co/{n}", (200,), Severity.LOW),
    ("Notion workspace",
     "https://www.notion.so/{n}", (200,), Severity.LOW),
    ("Cloudflare Pages",
     "https://{n}.pages.dev", (200, 301, 302), Severity.LOW),
    ("Cloudflare Workers",
     "https://{n}.workers.dev", (200, 301, 302), Severity.LOW),
    ("Vercel",
     "https://{n}.vercel.app", (200, 301, 302), Severity.LOW),
    ("Netlify",
     "https://{n}.netlify.app", (200, 301, 302), Severity.LOW),
    ("Heroku",
     "https://{n}.herokuapp.com", (200, 301, 302), Severity.LOW),
    ("AWS S3 cross-cloud (org bucket)",
     "https://{n}.s3.amazonaws.com", (200, 301, 302, 403), Severity.LOW),
]


async def probe(http: StealthClient, url: str, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        r = await http.head(url)
    if not r:
        async with sem:
            r = await http.get(url)
    return r.status_code if r else None


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    if "-" in brand:
        brand = brand.split("-")[0]
    if not brand or len(brand) < 3:
        return findings

    sem = asyncio.Semaphore(min(ctx.workers, 12))

    async def go(label: str, tpl: str, expected: tuple, sev: Severity) -> None:
        for n in variants(brand):
            url = tpl.replace("{n}", n)
            code = await probe(http, url, sem)
            if code and code in expected:
                # For S3, 403 sometimes means bucket exists but listing denied — still useful
                findings.append(lead(
                    phase="cross_saas", check="saas_tenant_exists",
                    title=f"{label} found: {url}",
                    target=url, severity=sev, confidence=Confidence.MEDIUM,
                    description=(
                        f"Org appears to have a presence at `{label}`. "
                        "Cross-SaaS attack surface — supply-chain risk and source for "
                        "additional OSINT (employees, repos, public content)."
                    ),
                    data={"label": label, "url": url, "status": code, "guess": n},
                ))
                break  # only flag first match per service

    await asyncio.gather(*(go(lbl, tpl, exp, sev) for lbl, tpl, exp, sev in PROBES))

    return findings
