"""Compute attack chains from tagged findings."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..models import ChainTag, Finding, Severity


# Plain-English label for each chain tag
TAG_LABEL: dict[ChainTag, str] = {
    ChainTag.TENANT_CONFIRMED: "Tenant exists and is reachable",
    ChainTag.TENANT_REGION_KNOWN: "Tenant region/cloud identified",
    ChainTag.TENANT_DOMAINS_ENUMERATED: "Tenant custom domains enumerated",
    ChainTag.TENANT_BRANDING_LEAKED: "Tenant has custom login branding",
    ChainTag.FED_AAD_CONNECT_PHS: "AAD Connect (PHS) likely deployed",
    ChainTag.FED_AAD_CONNECT_PTA: "AAD Connect (PTA) likely deployed",
    ChainTag.DNS_MX_O365: "MX confirms Exchange Online",
    ChainTag.DNS_AUTODISCOVER_O365: "Autodiscover CNAME confirms Exchange Online",
    ChainTag.DNS_ENTERPRISE_REGISTRATION: "AAD Device Registration enabled",
    ChainTag.DNS_ENTERPRISE_ENROLLMENT: "Intune Enrollment enabled",
    ChainTag.DNS_LYNCDISCOVER: "Lync/Teams discovery DNS record",
    ChainTag.DNS_MSOID_LEGACY: "Legacy `msoid` SSO record present",
    ChainTag.DNS_SIPFEDERATION: "Teams external chat SIP federation SRV",
    ChainTag.SVC_SHAREPOINT: "SharePoint Online present",
    ChainTag.SVC_ONEDRIVE: "OneDrive for Business present",
    ChainTag.SVC_EXCHANGE: "Exchange Online present",
    ChainTag.SVC_TEAMS: "Microsoft Teams reachable",
    ChainTag.SVC_LYNCDISCOVER: "Skype/Teams legacy discovery",
    ChainTag.SVC_YAMMER: "Yammer / Viva Engage present",
    ChainTag.SVC_STREAM: "Microsoft Stream present",
    ChainTag.SVC_LOOP: "Microsoft Loop present",
    ChainTag.SVC_WHITEBOARD: "Microsoft Whiteboard present",
    ChainTag.SVC_ECP: "Exchange Control Panel reachable",
    ChainTag.SVC_EWS: "Exchange Web Services reachable",
    ChainTag.SVC_ACTIVESYNC: "ActiveSync endpoint reachable",
    ChainTag.AZ_APPSERVICE: "Azure App Service hits",
    ChainTag.AZ_STATIC_WEBAPP: "Azure Static Web App hit",
    ChainTag.AZ_CONTAINER_APP: "Azure Container App hit",
    ChainTag.AZ_FRONT_DOOR: "Azure Front Door endpoint",
    ChainTag.AZ_CDN: "Azure CDN endpoint",
    ChainTag.AZ_BLOB: "Azure Blob storage account",
    ChainTag.AZ_FILE: "Azure File storage account",
    ChainTag.AZ_QUEUE: "Azure Queue storage account",
    ChainTag.AZ_TABLE: "Azure Table storage account",
    ChainTag.AZ_SERVICEBUS: "Azure Service Bus namespace",
    ChainTag.AZ_APIM: "Azure API Management gateway",
    ChainTag.AZ_COSMOS: "Azure Cosmos DB endpoint",
    ChainTag.AZ_SEARCH: "Azure Cognitive Search service",
    ChainTag.AZ_DEVOPS_ORG: "Azure DevOps org",
    ChainTag.PP_POWER_PAGES: "Power Pages portal",
    ChainTag.PP_DYNAMICS_ORG: "Dynamics 365 org",
    ChainTag.PP_COPILOT_M365: "M365 Copilot tenant detected",
    ChainTag.PP_COPILOT_STUDIO: "Copilot Studio in use",
    ChainTag.MCAS_TENANT: "Defender for Cloud Apps tenant",
    ChainTag.CTAP_INFERRED: "Cross-tenant access settings inferred",
    ChainTag.FED_MANAGED: "Tenant uses cloud-only auth",
    ChainTag.FED_FEDERATED: "Tenant federates to external IdP",
    ChainTag.FED_ADFS_DETECTED: "On-prem ADFS detected",
    ChainTag.FED_ADFS_MEX_EXPOSED: "ADFS MEX exposed externally",
    ChainTag.FED_THIRDPARTY_IDP: "Federates to 3rd-party IdP",
    ChainTag.FED_SEAMLESS_SSO: "Seamless SSO enabled (AAD Connect)",
    ChainTag.USER_ENUM_GETCREDTYPE: "Users enumerable via GetCredentialType",
    ChainTag.USER_ENUM_ONEDRIVE: "Users confirmed via OneDrive",
    ChainTag.USER_ENUM_TEAMS: "Users confirmed via Teams external search",
    ChainTag.USER_VALIDATED_NPLUS: "Users validated by ≥2 sources (high-confidence spray list)",
    ChainTag.LEGACY_AUTH_SMTP: "SMTP legacy auth surface reachable",
    ChainTag.LEGACY_AUTH_IMAP: "IMAP legacy auth surface reachable",
    ChainTag.LEGACY_AUTH_POP: "POP3 legacy auth surface reachable",
    ChainTag.LEGACY_AUTH_EWS_BASIC: "EWS basic auth surface reachable",
    ChainTag.LEGACY_AUTH_BLOCKED: "Conditional Access blocks legacy auth",
    ChainTag.MFA_GAP_DETECTED: "MFA gap (ROPC/legacy auth viable)",
    ChainTag.SMART_LOCKOUT_INFERRED: "Smart Lockout active",
    ChainTag.DEVICE_CODE_FLOW: "Device code flow available",
    ChainTag.FOCI_CLIENT_REACHABLE: "FOCI client accepts unauth probe",
    ChainTag.DNS_DMARC_NONE: "DMARC `p=none` (monitor only)",
    ChainTag.DNS_DMARC_QUARANTINE: "DMARC `p=quarantine`",
    ChainTag.DNS_DMARC_REJECT: "DMARC `p=reject`",
    ChainTag.DNS_DMARC_MISSING: "DMARC missing",
    ChainTag.DNS_SPF_OK: "SPF strict (-all)",
    ChainTag.DNS_SPF_PERMISSIVE: "SPF permissive (~all/+all)",
    ChainTag.DNS_SPF_MISSING: "SPF missing",
    ChainTag.DNS_DKIM_PRESENT: "DKIM selectors present",
    ChainTag.DNS_DKIM_MISSING: "DKIM missing",
    ChainTag.AZ_KUDU_EXPOSED: "Azure App Service Kudu (SCM) reachable",
    ChainTag.AZ_BLOB_PUBLIC_LISTING: "Azure Blob storage public listing",
    ChainTag.AZ_DEVOPS_PUBLIC_PROJECTS: "Azure DevOps public projects",
    ChainTag.AZ_DEVOPS_PUBLIC_WIKI: "Azure DevOps public wikis",
    ChainTag.AZ_CONTAINER_REGISTRY: "Azure Container Registry exposed",
    ChainTag.PP_POWER_PAGES_ODATA: "Power Pages OData (Dataverse) anonymously exposed",
    ChainTag.PP_POWER_BI_PUBLISH: "Power BI publish-to-web report",
    ChainTag.PP_COPILOT_PUBLIC_BOT: "Public Copilot Studio bot",
    ChainTag.APP_PROXY_PUBLIC: "AAD Application Proxy publishing on-prem app",
    ChainTag.SVC_OWA: "Outlook Web App reachable",
    ChainTag.SVC_BOOKINGS: "Microsoft Bookings page",
    ChainTag.SVC_FORMS: "Microsoft Forms",
}


# Attack-path templates: ordered list of tags → describes a path.
ATTACK_PATHS: list[dict[str, Any]] = [
    {
        "name": "Spoof-domain phishing chain",
        "needs": [ChainTag.DNS_DMARC_MISSING, ChainTag.USER_ENUM_GETCREDTYPE],
        "story": [
            "{DNS_DMARC_MISSING}: domain has no enforced DMARC",
            "{USER_ENUM_GETCREDTYPE}: valid user list harvested",
            "→ send spoofed mail from `{target}` with internal-style lure → harvest creds → MFA fatigue or device-code phish.",
        ],
        "alt_needs": [
            [ChainTag.DNS_DMARC_NONE, ChainTag.USER_ENUM_GETCREDTYPE],
            [ChainTag.DNS_SPF_PERMISSIVE, ChainTag.USER_ENUM_GETCREDTYPE],
            [ChainTag.DNS_SPF_MISSING, ChainTag.USER_ENUM_GETCREDTYPE],
        ],
        "effort": "low",
        "blast_radius": "credential theft, account takeover",
    },
    {
        "name": "Legacy-auth password spray",
        "needs": [ChainTag.LEGACY_AUTH_SMTP, ChainTag.USER_ENUM_GETCREDTYPE],
        "story": [
            "{LEGACY_AUTH_SMTP}: SMTP legacy auth surface reachable",
            "{USER_ENUM_GETCREDTYPE}: validated user list available",
            "→ slow spray with TrevorSpray over rotating IPs → ~5%–10% of orgs still hold one MFA-less account.",
        ],
        "alt_needs": [
            [ChainTag.MFA_GAP_DETECTED, ChainTag.USER_VALIDATED_NPLUS],
            [ChainTag.LEGACY_AUTH_IMAP, ChainTag.USER_VALIDATED_NPLUS],
            [ChainTag.LEGACY_AUTH_POP, ChainTag.USER_VALIDATED_NPLUS],
        ],
        "effort": "medium",
        "blast_radius": "M365 mailbox compromise",
    },
    {
        "name": "Device-code phishing",
        "needs": [ChainTag.DEVICE_CODE_FLOW, ChainTag.USER_ENUM_GETCREDTYPE],
        "story": [
            "{DEVICE_CODE_FLOW}: device code flow available unauth",
            "{USER_ENUM_GETCREDTYPE}: target user list ready",
            "→ pre-stage `microsoft.com/devicelogin` with a 9-digit code, send via {USER_ENUM_TEAMS:Teams} or email → user pastes code, attacker holds tokens.",
        ],
        "effort": "low",
        "blast_radius": "primary refresh tokens for Graph + Office",
    },
    {
        "name": "Golden SAML via on-prem ADFS",
        "needs": [ChainTag.FED_ADFS_DETECTED, ChainTag.FED_ADFS_MEX_EXPOSED],
        "story": [
            "{FED_ADFS_DETECTED}: tenant federated to on-prem ADFS",
            "{FED_ADFS_MEX_EXPOSED}: MEX endpoint exposed externally",
            "→ pivot inside corp net → exfil ADFS token-signing certificate (DKM key, mimikatz lsadump::dcsync /allusers) → forge SAML for any user → no-MFA access to all M365 services.",
        ],
        "effort": "high",
        "blast_radius": "tenant-wide impersonation",
    },
    {
        "name": "AAD Connect server hijack",
        "needs": [ChainTag.FED_SEAMLESS_SSO],
        "story": [
            "{FED_SEAMLESS_SSO}: Seamless SSO active (AAD Connect deployed)",
            "→ once on internal net, target the AAD Connect server (Tier-0) → extract MSOL_ account creds → DCSync → full domain compromise → AAD identity sync write.",
        ],
        "effort": "high",
        "blast_radius": "on-prem AD + Entra full compromise",
    },
    {
        "name": "Public Power Pages Dataverse exfil",
        "needs": [ChainTag.PP_POWER_PAGES_ODATA],
        "story": [
            "{PP_POWER_PAGES_ODATA}: Power Pages anonymously exposes OData",
            "→ enumerate exposed entities at `/_odata/$metadata` → bulk-pull tables (often Customers, Contacts, Cases) → sensitive data exfil.",
        ],
        "effort": "low",
        "blast_radius": "Dataverse data leak (often PII)",
    },
    {
        "name": "Azure Blob anonymous data exfil",
        "needs": [ChainTag.AZ_BLOB_PUBLIC_LISTING],
        "story": [
            "{AZ_BLOB_PUBLIC_LISTING}: storage account allows anonymous container listing",
            "→ enumerate containers → wholesale download of blobs (backups, configs, source code, customer data).",
        ],
        "effort": "low",
        "blast_radius": "data exfil + secrets in committed configs",
    },
    {
        "name": "Azure DevOps public-project credential leak",
        "needs": [ChainTag.AZ_DEVOPS_PUBLIC_PROJECTS],
        "story": [
            "{AZ_DEVOPS_PUBLIC_PROJECTS}: org allows public projects, anonymously listable",
            "→ scan source repos and wikis for `secret`, `key`, `password`, `connectionstring` → pivot into private resources or third-party services.",
        ],
        "effort": "low",
        "blast_radius": "source / secret leak; pivot into infra",
    },
    {
        "name": "Kudu code-exec on Azure App Service",
        "needs": [ChainTag.AZ_KUDU_EXPOSED],
        "story": [
            "{AZ_KUDU_EXPOSED}: SCM endpoint reachable",
            "→ if creds harvested via spray/phish or basic publishing creds enabled → ZIP deploy webshell → env var exfil → managed identity → tenant lateral movement.",
        ],
        "effort": "medium",
        "blast_radius": "App Service code exec; managed-identity pivot",
    },
    {
        "name": "App Proxy direct attack on legacy app",
        "needs": [ChainTag.APP_PROXY_PUBLIC],
        "story": [
            "{APP_PROXY_PUBLIC}: AAD App Proxy publishes on-prem app to internet",
            "→ if app uses pre-auth=passthrough OR a CVE-vuln app behind it → direct internet → on-prem internal app exploit.",
        ],
        "effort": "medium",
        "blast_radius": "depends on published app; often legacy intranet web apps",
    },
    {
        "name": "Public Copilot Studio bot prompt-injection",
        "needs": [ChainTag.PP_COPILOT_STUDIO],
        "story": [
            "{PP_COPILOT_STUDIO}: tenant uses Copilot Studio",
            "→ run mbrg/power-pwn to enumerate publicly-published bots → prompt-inject to exfil tenant data the bot can access.",
        ],
        "effort": "low",
        "blast_radius": "data exfil via the bot's authorized scope",
    },
]


def _present_tags(findings: list[Finding]) -> set[ChainTag]:
    s: set[ChainTag] = set()
    for f in findings:
        s.update(f.tags)
    return s


def _format_story(template: list[str], tags_present: set[ChainTag], target: str) -> list[str]:
    lines = []
    for raw in template:
        line = raw.replace("{target}", target)
        for tag in ChainTag:
            # Accept both the dash-form (TAG.value) and underscore-form (TAG.name)
            for token in (tag.value, tag.name):
                line = line.replace(f"{{{token}}}", TAG_LABEL.get(tag, tag.value))
                placeholder = f"{{{token}:"
                while placeholder in line:
                    start = line.index(placeholder)
                    end = line.index("}", start)
                    fallback = line[start + len(placeholder): end]
                    replacement = TAG_LABEL.get(tag, tag.value) if tag in tags_present else fallback
                    line = line[:start] + replacement + line[end + 1:]
        lines.append(line)
    return lines


def build_chain(findings: list[Finding], target: str) -> dict[str, Any]:
    """Construct the attack-path roll-up + raw graph."""
    present = _present_tags(findings)

    # Build flat graph data
    graph_nodes: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    for f in findings:
        for tag in f.tags:
            if tag.value in seen_nodes:
                continue
            seen_nodes.add(tag.value)
            graph_nodes.append({
                "tag": tag.value,
                "label": TAG_LABEL.get(tag, tag.value),
                "phase": f.phase,
            })

    edges: list[dict[str, Any]] = []
    for f in findings:
        for tag in f.tags:
            for enabled in f.enables:
                edges.append({"from": tag.value, "to": enabled})

    # Find triggered paths
    paths_hit: list[dict[str, Any]] = []
    for tmpl in ATTACK_PATHS:
        triggers = [tmpl["needs"]] + tmpl.get("alt_needs", [])
        for need_set in triggers:
            if all(t in present for t in need_set):
                paths_hit.append({
                    "name": tmpl["name"],
                    "effort": tmpl["effort"],
                    "blast_radius": tmpl["blast_radius"],
                    "tags": [t.value for t in need_set],
                    "story": _format_story(tmpl["story"], present, target),
                })
                break

    # Score by impact (rough heuristic)
    severity_weight = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
    return {
        "target": target,
        "tags_present": sorted(t.value for t in present),
        "nodes": graph_nodes,
        "edges": edges,
        "attack_paths": paths_hit,
        "summary": {
            "total_findings": len(findings),
            "total_tags": len(present),
            "total_paths": len(paths_hit),
            "by_severity": {
                s.value: sum(1 for f in findings if f.severity == s)
                for s in Severity
            },
        },
    }


def render_mermaid(chain: dict[str, Any]) -> str:
    """Generate a Mermaid graph DSL string."""
    lines = ["```mermaid", "graph LR"]
    for n in chain["nodes"]:
        lines.append(f'    {n["tag"].replace("-", "_")}["{n["label"]}"]')
    for e in chain["edges"]:
        a = e["from"].replace("-", "_")
        b = e["to"].replace("-", "_").replace(" ", "_")
        lines.append(f'    {a} --> {b}["{e["to"]}"]')
    lines.append("```")
    return "\n".join(lines)


def render_attack_paths_md(chain: dict[str, Any]) -> str:
    out = [f"# Attack Paths — {chain['target']}\n"]
    if not chain["attack_paths"]:
        out.append("_No multi-step attack paths triggered. Findings will still be useful — review the `findings.json` for atomic leads._\n")
        return "\n".join(out)

    for i, p in enumerate(chain["attack_paths"], 1):
        out.append(f"\n## {i}. {p['name']}\n")
        out.append(f"- **Effort:** {p['effort']}")
        out.append(f"- **Blast radius:** {p['blast_radius']}")
        out.append(f"- **Triggering tags:** {', '.join(p['tags'])}\n")
        for line in p["story"]:
            out.append(f"- {line}")
    out.append("\n---\n")
    out.append("\n## Graph\n")
    out.append(render_mermaid(chain))
    return "\n".join(out)
