"""Phase 51 — Final-cleanup coverage for remaining v0.1.8 audit gaps.

Closes the explicit residual list:
- Power Platform connector enumeration (flow.microsoft.com)
- Azure AI Foundry / AI Studio (ai.azure.com)
- Azure Service Fabric (port 19080 admin)
- Azure VM / VMSS direct FQDN probes
- Azure Container Instances (ACI)
- Azure VPN Gateway / ExpressRoute deep-link
- Azure Relay (*.servicebus.windows.net/$relay)
- Azure Notification Hubs (standalone)
- Azure Stream Analytics / Time Series Insights
- CAE (Continuous Access Evaluation) inference
- Insider Risk Management deep-link
- Power Virtual Agents bot enum

Read-only existence checks; output is hunt-pack guidance for items that
require auth or can only be discovered via OSINT.
"""
from __future__ import annotations

import asyncio

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, is_existence_signal


REGIONS = ["westeurope", "eastus", "westus", "northeurope", "centralus",
           "uksouth", "australiaeast", "japaneast", "eastus2", "westus2"]


def variants(brand: str) -> list[str]:
    if not brand or len(brand) < 3:
        return []
    return list(dict.fromkeys([
        brand, f"{brand}-prod", f"{brand}sf", f"{brand}-sf",
        f"{brand}vm", f"{brand}-vm", f"{brand}-aci", f"{brand}aci",
        f"{brand}-vpn", f"{brand}-relay", f"{brand}-nh", f"{brand}-stream",
        f"{brand}-tsi", f"{brand}-foundry", f"{brand}-ai-foundry",
        f"{brand}bot", f"{brand}-bot",
    ]))


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

    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "") or brand
    tid = snap.tenant_id or ""

    sem = asyncio.Semaphore(min(ctx.workers, 12))

    # ---- 1. Power Platform connectors enumeration deep-link ----
    if tid:
        findings.append(data(
            phase="final_gaps", check="powerplatform_connectors_deep_link",
            title="Power Platform connectors admin deep-link (auth-gated)",
            target=f"https://make.powerautomate.com/?tenantId={tid}",
            confidence=Confidence.HIGH,
            payload={
                "url": f"https://make.powerautomate.com/environments/Default-{tid}/connections",
                "shared_connections": f"https://make.powerautomate.com/environments/Default-{tid}/connections/shared",
                "approach": "Auth required. Exposes which 3rd-party services this tenant has connected (Office 365, Salesforce, Dropbox, Slack, etc).",
                "github_dorks": [
                    f'"{brand}" "powerautomate" "/connections/"',
                    f'"flow.microsoft.com" "{tid}" "connections"' if tid else f'"flow.microsoft.com" "{brand}"',
                ],
            },
        ))

    # ---- 2. Azure AI Foundry (ai.azure.com) ----
    if tid:
        findings.append(data(
            phase="final_gaps", check="azure_ai_foundry_deep_link",
            title="Azure AI Foundry / AI Studio (auth-gated)",
            target=f"https://ai.azure.com/?tid={tid}",
            confidence=Confidence.HIGH,
            payload={
                "url": f"https://ai.azure.com/?tenantId={tid}",
                "approach": "Universal AI Foundry portal. Tenant-specific projects auth-gated.",
                "endpoint_pattern": "Most AI Foundry projects also expose Azure OpenAI endpoints (covered in azure_subdomain_enum).",
            },
        ))

    # ---- 3. Azure Service Fabric: {name}.{region}.cloudapp.azure.com:19080 ----
    async def service_fabric(name: str, region: str) -> None:
        url = f"https://{name}.{region}.cloudapp.azure.com:19080"
        code = await probe_url(http, url, sem)
        if code in (200, 401, 403):
            findings.append(lead(
                phase="final_gaps", check="service_fabric_explorer",
                title=f"Service Fabric Explorer reachable: {url}",
                target=url, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description=(
                    "Service Fabric admin endpoint (port 19080) is internet-reachable. "
                    "If unauthenticated, this is the cluster admin UI. If auth-gated, "
                    "still a recon signal — many SF clusters auth via cert-based admin."
                ),
                data={"url": url, "name": name, "region": region, "status": code,
                      "explorer_url": f"https://{name}.{region}.cloudapp.azure.com:19080/Explorer"},
            ))

    for n in variants(brand)[:3]:
        await asyncio.gather(*(service_fabric(n, r) for r in REGIONS[:5]))

    # ---- 4. Azure VM / VMSS — direct FQDN probes (cloudapp.net legacy + cloudapp.azure.com) ----
    async def vm_probe(name: str, region: str) -> None:
        for suffix in (f".{region}.cloudapp.azure.com", ".cloudapp.net"):
            url = f"https://{name}{suffix}"
            code = await probe_url(http, url, sem)
            if code and code in (200, 301, 302, 401, 403):
                findings.append(lead(
                    phase="final_gaps", check="azure_vm_endpoint",
                    title=f"Azure VM / cloud-service endpoint: {url}",
                    target=url, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                    data={"url": url, "name": name, "region": region, "status": code,
                          "note": "Could be VM, VMSS, legacy Cloud Service, or Service Fabric. "
                                  "Cross-reference with subdomain_takeover phase for dangling check."},
                ))

    for n in variants(brand)[:2]:
        await asyncio.gather(*(vm_probe(n, r) for r in REGIONS[:4]))

    # ---- 5. Azure Container Instances (ACI) — uses cloudapp.azure.com domain too ----
    # ACI doesn't have a unique suffix; fqdns follow {dnslabel}.{region}.azurecontainer.io
    async def aci_probe(name: str, region: str) -> None:
        url = f"https://{name}.{region}.azurecontainer.io"
        code = await probe_url(http, url, sem)
        if code and code in (200, 301, 302, 401, 403, 404):
            if code != 404:
                findings.append(lead(
                    phase="final_gaps", check="azure_container_instance",
                    title=f"Azure Container Instance reachable: {url}",
                    target=url, severity=Severity.LOW, confidence=Confidence.HIGH,
                    data={"url": url, "name": name, "region": region, "status": code},
                ))

    for n in variants(brand)[:3]:
        await asyncio.gather(*(aci_probe(n, r) for r in REGIONS[:5]))

    # ---- 6. Azure VPN Gateway / ExpressRoute — admin deep-links ----
    if tid:
        findings.append(data(
            phase="final_gaps", check="azure_network_admin_deep_links",
            title="Azure VPN Gateway / ExpressRoute admin deep-links (auth-gated)",
            target=f"https://portal.azure.com/?tid={tid}",
            confidence=Confidence.MEDIUM,
            payload={
                "vpn_gateway_blade": f"https://portal.azure.com/?tid={tid}#browse/Microsoft.Network%2FvirtualNetworkGateways",
                "expressroute_blade": f"https://portal.azure.com/?tid={tid}#browse/Microsoft.Network%2FexpressRouteCircuits",
                "approach": "Auth required. Universal portal blades; tenant-scoped via ?tid=.",
            },
        ))

    # ---- 7. Azure Relay: {name}.servicebus.windows.net/$relay ----
    async def relay_probe(name: str) -> None:
        url = f"https://{name}.servicebus.windows.net/$relay"
        code = await probe_url(http, url, sem)
        if code in (200, 401, 403, 404):
            if code != 404:
                findings.append(lead(
                    phase="final_gaps", check="azure_relay_endpoint",
                    title=f"Azure Relay endpoint: {url}",
                    target=url, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                    data={"url": url, "name": name, "status": code,
                          "note": "Relay shares Service Bus namespace; existence indicates hybrid-connection usage."},
                ))

    for n in variants(brand)[:3]:
        await relay_probe(n)

    # ---- 8. Azure Notification Hubs (standalone; uses servicebus.windows.net) ----
    async def nh_probe(name: str) -> None:
        # NH namespace at {name}.servicebus.windows.net (shared with SB)
        # Distinct probe: try the NH-specific path
        url = f"https://{name}.servicebus.windows.net/{name}-hub/messages"
        code = await probe_url(http, url, sem)
        if code in (401, 403):
            findings.append(lead(
                phase="final_gaps", check="azure_notification_hub",
                title=f"Azure Notification Hub probable: {url}",
                target=url, severity=Severity.LOW, confidence=Confidence.MEDIUM,
                data={"url": url, "name": name, "status": code,
                      "note": "Auth required; existence indicates push-notification infrastructure."},
            ))

    for n in variants(brand)[:3]:
        await nh_probe(n)

    # ---- 9. Stream Analytics / Time Series Insights — admin deep-links ----
    if tid:
        findings.append(data(
            phase="final_gaps", check="azure_stream_tsi_deep_links",
            title="Azure Stream Analytics / Time Series Insights deep-links (auth-gated)",
            target=f"https://portal.azure.com/?tid={tid}",
            confidence=Confidence.MEDIUM,
            payload={
                "stream_analytics": f"https://portal.azure.com/?tid={tid}#browse/Microsoft.StreamAnalytics%2FStreamingJobs",
                "tsi": f"https://portal.azure.com/?tid={tid}#browse/Microsoft.TimeSeriesInsights%2Fenvironments",
                "tsi_explorer_pattern": "https://insights.timeseries.azure.com/?envFqdn={env-id}.env.timeseries.azure.com",
            },
        ))

    # ---- 10. CAE (Continuous Access Evaluation) — inference guidance ----
    findings.append(data(
        phase="final_gaps", check="cae_inference_guidance",
        title="CAE (Continuous Access Evaluation) inference guidance",
        target=apex, confidence=Confidence.MEDIUM,
        payload={
            "approach": [
                "CAE state is observable from token claims (xms_cc claim or `cae` capability).",
                "Tokens issued for tenants with CAE enabled have shorter effective lifetimes for sensitive operations.",
                "Anonymous detection: not directly possible.",
                "Authenticated detection: parse the `xms_cc` capability from any token issued to the tenant; CAE-enforcing tokens contain `CP1` capability flag.",
            ],
            "audit_value": "Tenants without CAE leak token revocations during incident response (compromised tokens remain valid until lifetime expiry).",
        },
    ))

    # ---- 11. Insider Risk Management — admin deep-link ----
    if tid:
        findings.append(data(
            phase="final_gaps", check="insider_risk_admin_deep_link",
            title="Microsoft Purview Insider Risk Management (auth-gated)",
            target=f"https://compliance.microsoft.com/?tid={tid}",
            confidence=Confidence.MEDIUM,
            payload={
                "url": f"https://compliance.microsoft.com/insiderriskmgmt?tid={tid}",
                "approach": "Auth required. Existence indicates org has IRM policies — sensitive data classification + behavioral monitoring.",
            },
        ))

    # ---- 12. Power Virtual Agents / Copilot Studio bot enum (deeper than copilot.py) ----
    # PVA bots are at https://{tenant}.crm{region}.dynamics.com/copilotstudio/...
    # OR https://copilotstudio.microsoft.com/environments/{env_id}/bots/...
    if tenant_short:
        bot_universal = f"https://copilotstudio.microsoft.com/environments/Default-{tid}/bots"
        async with sem:
            code = await probe_url(http, bot_universal, sem)
        findings.append(data(
            phase="final_gaps", check="copilot_studio_bot_enum_link",
            title="Copilot Studio bot enumeration deep-link (auth-gated)",
            target=bot_universal, confidence=Confidence.MEDIUM,
            payload={
                "url": bot_universal, "status": code,
                "deep_dive_tool": "power-pwn (https://github.com/mbrg/power-pwn) — for authenticated bot enumeration",
                "anonymous_bot_pattern": "https://web.powerva.microsoft.com/environments/{env}/bots/{bot_id}/webchat",
            },
        ))

    return findings
