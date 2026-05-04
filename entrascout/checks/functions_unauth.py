"""Phase 32 — Azure Function App unauth API hunt.

For each App Service / Function App detected by `azure_resources`, brute-force
common Function names against `/api/{name}`. Anonymous-AuthLevel functions
respond 200 / 202; auth-required ones respond 401.

Common Function patterns: HTTP triggers from quickstarts and samples are
re-used heavily and rarely renamed by developers.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, issue


# Common Function names (from Microsoft samples + frequent in-the-wild names)
FUNCTION_NAMES = [
    # Generic HTTP triggers from quickstarts
    "httptrigger", "httptrigger1", "httptrigger2", "httpexample", "function1",
    "test", "hello", "hellohttp", "echo", "ping", "health", "healthcheck",
    "status", "version", "info",
    # Webhook patterns
    "webhook", "webhooks", "callback", "trigger", "event", "events",
    "notify", "notification", "notifications",
    # Auth / token
    "auth", "authorize", "token", "refresh", "login", "logout",
    "session", "sessions", "verify", "validate",
    # Data ops
    "submit", "process", "receive", "publish", "queue", "dispatch",
    "send", "sendmail", "sendsms", "sendalert",
    # Domain-specific
    "user", "users", "users-create", "users-list",
    "order", "orders", "payment", "payments",
    "search", "query", "lookup", "find",
    "upload", "download", "export", "import",
    # Admin / debug
    "admin", "debug", "log", "logs", "monitor",
    # Power Automate / Logic Apps callable
    "manual", "manualtrigger", "run",
]


async def probe_function(http: StealthClient, base: str, fn: str, sem: asyncio.Semaphore) -> tuple[str, int | None, str]:
    """Returns (function_name, status_code, snippet)."""
    url = f"{base}/api/{fn}"
    async with sem:
        r = await http.get(url, headers={"Accept": "application/json, text/plain, */*"})
    if not r:
        return fn, None, ""
    snippet = (r.text or "")[:200] if hasattr(r, "text") else ""
    return fn, r.status_code, snippet


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []

    # Find App Services / Function Apps from prior findings.
    # IMPORTANT: exclude .scm.azurewebsites.net — that's Kudu (deployment console),
    # not the user's Function App. Probing /api/* on Kudu just hits the Kudu auth flow
    # which always returns 200 with an Azure AD login page (Easy Auth) — false positives.
    bases: set[str] = set()
    for f in om.findings:
        target = f.target or ""
        if ".azurewebsites.net" in target and ".scm.azurewebsites.net" not in target:
            base = target.rstrip("/")
            if base.startswith("https://"):
                host = base.replace("https://", "").split("/")[0]
                if host.endswith(".azurewebsites.net") and ".scm." not in host and "-staging" not in host:
                    bases.add(f"https://{host}")
    bases_list = sorted(bases)[:5]  # cap to avoid runaway

    if not bases_list:
        return findings

    sem = asyncio.Semaphore(min(ctx.workers, 12))

    for base in bases_list:
        results = await asyncio.gather(*(probe_function(http, base, fn, sem) for fn in FUNCTION_NAMES))
        for fn, code, snippet in results:
            if code is None:
                continue
            url = f"{base}/api/{fn}"
            # Easy Auth fingerprints — 200 returned but it's actually an AAD login page
            EASY_AUTH_FINGERPRINTS = (
                "Sign in to your account",
                "login.microsoftonline.com",
                ".azureedge.net/aadcdn",
                "<title>Redirecting</title>",
                "easyauth",
                "PageTitleAppName",
            )
            is_easy_auth = any(fp.lower() in (snippet or "").lower() for fp in EASY_AUTH_FINGERPRINTS)
            if code == 200 and not is_easy_auth:
                # Anonymous-callable Function endpoint — high signal
                findings.append(issue(
                    phase="functions_unauth", check="function_anonymous_callable",
                    title=f"Azure Function App endpoint anonymously callable (200): {url}",
                    target=url, severity=Severity.HIGH, confidence=Confidence.HIGH,
                    description=(
                        f"The Function endpoint `/api/{fn}` returned 200 to an anonymous GET. "
                        f"This indicates the function's `authLevel` is `anonymous`. Without "
                        f"input validation, this is a remote-execution surface."
                    ),
                    data={"url": url, "function": fn, "base": base, "status": code,
                          "response_snippet": snippet},
                    tags=[ChainTag.AZ_APPSERVICE],
                    recommendation=(
                        "If anonymous access is intended, document it as such; otherwise "
                        "raise the function's `authLevel` to `function` (key required) or "
                        "use Easy Auth in front of the Function App."
                    ),
                ))
            elif code == 200 and is_easy_auth:
                # Easy Auth — it's PROTECTED by AAD login redirect, NOT an anon-callable function
                # Don't emit a finding — this is normal protected-app behavior
                pass
            elif code == 202:
                findings.append(issue(
                    phase="functions_unauth", check="function_async_anonymous",
                    title=f"Azure Function async-accepted anonymously (202): {url}",
                    target=url, severity=Severity.HIGH, confidence=Confidence.HIGH,
                    description="Function returned 202 Accepted — anonymous queue/async trigger.",
                    data={"url": url, "function": fn, "base": base, "status": code},
                    tags=[ChainTag.AZ_APPSERVICE],
                ))
            elif code == 401:
                # Endpoint exists but key required — useful intel
                findings.append(data(
                    phase="functions_unauth", check="function_key_required",
                    title=f"Azure Function endpoint requires key: {url}",
                    target=url, confidence=Confidence.HIGH,
                    payload={"url": url, "function": fn, "base": base, "status": code,
                             "interpretation": "Endpoint exists; `authLevel: function` (key required). Audit code repos for the function key."},
                ))
            # 404 = function does not exist; 405 = wrong method (could try POST) — out of scope

    return findings
