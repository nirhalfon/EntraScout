"""Phase 16 — Azure resource subdomain enumeration (gaps #3, #6, #11, #26).

Probes well-known Azure DNS namespaces against guessed names derived from the
tenant brand: Key Vault, Cognitive Services / OpenAI, App Service deployment
slots, Recovery Services vaults.

Existence-only (HEAD/GET → 401/404 differential). No exploit attempts.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, validation, is_existence_signal


# Suffix templates per service. {n} = brand-derived guess.
KEYVAULT_SUFFIXES = ["{n}", "{n}-kv", "{n}kv", "{n}prod", "{n}-prod-kv",
                     "{n}vault", "kv-{n}", "vault-{n}", "{n}-secrets", "{n}-keyvault"]
OPENAI_SUFFIXES = ["{n}", "{n}-openai", "{n}openai", "{n}-ai", "{n}ai",
                   "{n}-prod-openai", "openai-{n}"]
COGNITIVE_SUFFIXES = ["{n}", "{n}-cog", "{n}cog", "{n}-cognitive", "cog-{n}"]
RECOVERY_VAULT_SUFFIXES = ["{n}-rsv", "{n}rsv", "{n}-recoveryvault", "{n}-backup",
                            "rsv-{n}", "recovery-{n}", "{n}-vault"]
APP_SLOT_SUFFIXES = ["{n}-staging", "{n}-stage", "{n}-dev", "{n}-test",
                      "{n}-uat", "{n}-qa", "{n}-preview", "staging-{n}", "dev-{n}", "test-{n}"]


def expand(template_list: list[str], brand: str) -> list[str]:
    out: list[str] = []
    for t in template_list:
        n = t.format(n=brand)
        if 3 <= len(n) <= 24 and n.replace("-", "").isalnum():
            out.append(n)
    return list(dict.fromkeys(out))  # dedupe, preserve order


async def probe_url(http: StealthClient, url: str, sem: asyncio.Semaphore) -> int | None:
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

    # ---- Azure Key Vault: *.vault.azure.net ----
    async def kv(name: str) -> None:
        url = f"https://{name}.vault.azure.net"
        code = await probe_url(http, url, sem)
        if code and code in (401, 403, 200):
            # Key Vault always replies 401 on unauth root — that's our existence signal.
            findings.append(lead(
                phase="azure_subdomain_enum", check="keyvault_exists",
                title=f"Azure Key Vault exists: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                description=(
                    "Anonymous probe confirmed a Key Vault under this name. Vault contents are "
                    "auth-gated; this finding is reconnaissance — name match suggests this Key "
                    "Vault belongs to the target. Check internal references in code/repos for "
                    "this exact vault name to find leaked SAS URLs / managed-identity tokens."
                ),
                data={"url": url, "vault_name": name, "status": code},
                tags=[ChainTag.AZ_KEYVAULT],
                recommendation="Audit code repos and CI configs for references to this Key Vault. Ensure SAS / access policies are minimal.",
            ))

    await asyncio.gather(*(kv(n) for n in expand(KEYVAULT_SUFFIXES, brand)))

    # ---- Azure OpenAI: *.openai.azure.com ----
    async def oai(name: str) -> None:
        url = f"https://{name}.openai.azure.com"
        code = await probe_url(http, url, sem)
        if code and code in (401, 403, 200, 404):
            # 401 = exists; 404 = name available; we want existence signals
            if code != 404:
                findings.append(lead(
                    phase="azure_subdomain_enum", check="openai_endpoint_exists",
                    title=f"Azure OpenAI endpoint exists: {url}",
                    target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                    description="Azure OpenAI endpoint discovered. Auth-gated; recon signal.",
                    data={"url": url, "name": name, "status": code},
                    tags=[ChainTag.AZ_OPENAI],
                ))

    await asyncio.gather(*(oai(n) for n in expand(OPENAI_SUFFIXES, brand)))

    # ---- Azure Cognitive Services: *.cognitiveservices.azure.com ----
    async def cog(name: str) -> None:
        url = f"https://{name}.cognitiveservices.azure.com"
        code = await probe_url(http, url, sem)
        if code and code in (401, 403):
            findings.append(lead(
                phase="azure_subdomain_enum", check="cognitive_services_exists",
                title=f"Azure Cognitive Services endpoint exists: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                data={"url": url, "name": name, "status": code},
                tags=[ChainTag.AZ_COGNITIVE],
            ))

    await asyncio.gather(*(cog(n) for n in expand(COGNITIVE_SUFFIXES, brand)))

    # ---- Recovery Services Vault: *.{region}.recovery.windowsazure.com ----
    # The vault.azure.net namespace is shared with Key Vault; recovery vaults are
    # at .recovery.windowsazure.com per region. Without region info, probe the
    # standard frontend.
    # Skipping deep region enum here — reserved for v0.1.7

    # ---- App Service deployment slots: {app}-{slot}.azurewebsites.net ----
    # We only know there ARE App Services if azure_resources.py already detected them.
    # Look at prior findings.
    prior_app_services = []
    for f in om.findings:
        if f.check == "appservice_exists" or "azurewebsites.net" in (f.target or ""):
            target = f.target or ""
            if ".azurewebsites.net" in target:
                base = target.replace("https://", "").replace("http://", "").split(".")[0]
                if base and "-" not in base:  # prefer non-slot bases
                    prior_app_services.append(base)
    prior_app_services = list(set(prior_app_services))

    async def slot(app: str, suffix_template: str) -> None:
        slot_name = suffix_template.format(n=app)
        if slot_name == app:
            return
        url = f"https://{slot_name}.azurewebsites.net"
        code = await probe_url(http, url, sem)
        if code and code in (200, 301, 302, 401, 403):
            findings.append(lead(
                phase="azure_subdomain_enum", check="app_service_slot_exists",
                title=f"App Service deployment slot reachable: {url}",
                target=url, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                description=(
                    "Deployment slot discovered. Slots often share infrastructure with the "
                    "primary app but may have different WAF rules, auth config, or be running "
                    "older code. Compare /robots.txt, /.well-known/, and observable headers."
                ),
                data={"url": url, "primary": app, "slot": slot_name, "status": code},
                tags=[ChainTag.AZ_APPSERVICE_SLOT],
                recommendation="Audit deployment slot exposure — staging slots should not be internet-reachable in most configurations.",
            ))

    for app in prior_app_services[:5]:
        await asyncio.gather(*(slot(app, t) for t in APP_SLOT_SUFFIXES))

    return findings
