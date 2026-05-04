"""Phase 48 — Webhook URL leak hunt-pack.

Webhook URLs that grant remote-execution-like primitives when leaked:
- Microsoft Teams incoming webhooks (`*.webhook.office.com/webhookb2/...`)
- Outlook actionable messages (`outlook.office.com/connectors/...`)
- Power Automate / Logic Apps trigger SAS URLs (covered in logic_apps too)
- Azure Functions authLevel=function URLs with `?code=` SAS keys
- Slack / Discord / GitHub repo webhooks for the org (cross-SaaS)
"""
from __future__ import annotations

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    apex = (snap.primary_domain or ctx.target).lower()
    brand = apex.split(".")[0]
    tid = snap.tenant_id or ""

    findings.append(data(
        phase="webhook_hunt", check="webhook_url_hunt_pack",
        title=f"Webhook URL leak hunt-pack ({brand} / {apex})",
        target=apex, confidence=Confidence.HIGH,
        payload={
            "ms_teams_incoming_webhook": {
                "pattern": "https://{tenant}.webhook.office.com/webhookb2/{guid1}@{tid}/IncomingWebhook/{wid}/{guid2}",
                "github_dorks": [
                    f'"{brand}" "webhook.office.com/webhookb2"',
                    f'"webhookb2" "{tid}"' if tid else f'"webhookb2" "{brand}"',
                ],
                "impact": "Anonymous post-to-channel — phishing-via-Teams, incident noise.",
            },
            "outlook_connector": {
                "pattern": "https://outlook.office.com/connectors/{...}",
                "github_dorks": [
                    f'"{brand}" "outlook.office.com/connectors"',
                    f'"office.com/connectors" {brand}',
                ],
            },
            "logic_app_trigger": {
                "pattern": "https://prod-NN.{region}.logic.azure.com/workflows/{guid}/triggers/manual/paths/invoke?api-version=...&sp=/triggers/manual/run&sv=1.0&sig=...",
                "see": "logic_apps phase",
            },
            "azure_function_with_code": {
                "pattern": "https://{app}.azurewebsites.net/api/{name}?code={key}",
                "github_dorks": [
                    f'"{brand}" "azurewebsites.net/api" "code="',
                    f'"{brand}" "?code=" filename:.env',
                ],
            },
            "slack_webhook": {
                "pattern": "https://hooks.slack.com/services/T*/B*/...",
                "github_dorks": [
                    f'"{brand}" "hooks.slack.com/services/"',
                ],
                "impact": "Anonymous post-to-Slack.",
            },
            "discord_webhook": {
                "pattern": "https://discord.com/api/webhooks/{...}/{...}",
                "github_dorks": [
                    f'"{brand}" "discord.com/api/webhooks/"',
                ],
            },
            "github_repo_webhook": {
                "pattern": "https://github.com/{org}/{repo}/settings/hooks",
                "approach": "Org-public repos may expose webhook destinations in workflow logs.",
            },
        },
    ))

    return findings
