# Phase Reference

EntraScout runs **52 phases** across the entire Microsoft cloud surface.

!!! tip "Selecting phases"
    Use `--phases` with numbers (`1,2,29`) or names (`tenant,federation`).

## Identity & Federation

| # | Phase | Description |
|---|---|---|
| 1 | `tenant` | Tenant fingerprint (ID, region, cloud, branding) |
| 2 | `federation` | Federation type + ADFS deep (MEX, RP catalog, ClaimsXray) |
| 3 | `user_enum` | User enumeration (GetCredentialType, OneDrive timing, Teams) |
| 7 | `oauth` | Token / OAuth (FOCI client probing, device-code surface) |
| 14 | `identity_edges` | AAD App Proxy, Defender for Cloud Apps tenant, DRS endpoints |
| 17 | `aad_apps` | App Registration enum, B2C tenant, Graph metadata |
| 43 | `entra_advanced` | External ID + OIDC, Verified ID, Workload, Governance, ZTNA, PIM |
| 46 | `cross_saas` | 15 cross-SaaS tenant existence probes (Atlassian/Slack/Zoom/etc.) |

## M365 Services

| # | Phase | Description |
|---|---|---|
| 4 | `m365_services` | M365 service surface (SP, OneDrive, Exchange, Teams, Yammer, Lync) |
| 29 | `sharepoint_recon` | SharePoint deep (site enum, REST API, anonymous search-API test) |
| 44 | `teams_deep` | Teams Live Events / Webinars + incoming-webhook hunt + Phone System |
| 45 | `office_extras` | OneNote, Office Online, Lists consumer, Clipchamp, Editor |

## Azure Resources

| # | Phase | Description |
|---|---|---|
| 13 | `azure_resources` | Azure resources (App Service, Kudu, Storage, ACR, SWA, FD, CDN, etc.) |
| 15 | `ms_public_content` | Bookings, Forms, Stream, Loop, Power BI public, Yammer external |
| 16 | `azure_subdomain_enum` | Key Vault, OpenAI, Cognitive, App Service deployment slots |
| 30 | `azure_data_services` | Cosmos / SQL / Redis / Data Lake / Event Grid / IoT / SB / Container Apps |
| 38 | `azure_compute_extras` | AKS public API, Service Fabric, Batch, Spring Apps, Lab Services |
| 39 | `azure_data_extras` | Synapse, Data Factory, Databricks, HDInsight, AML, Health Bot, FHIR |
| 40 | `azure_network_extras` | SignalR, Web PubSub, Bastion, Private Link DNS leak |
| 42 | `dynamics_deep` | D365 CRM Web API direct, Power Pages vanity domains, AppSource |
| 49 | `subscription_leak` | Azure subscription ID leak hunt-pack + GUID extraction |

## Auth & MFA

| # | Phase | Description |
|---|---|---|
| 6 | `auth_surface` | Auth attack surface (legacy banners, ROPC, AADSTS, lockout, device-code) |
| 8 | `defense_posture` | Defense roll-up (mail spoofing, legacy auth, ADFS exposure) |
| 31 | `mfa_gaps` | MFA bypass surfaces (EXO basic auth, ADFS WS-Trust, ROPC) |
| 32 | `functions_unauth` | Azure Function App `/api/{name}` brute force |

## DNS & Network

| # | Phase | Description |
|---|---|---|
| 5 | `dns_surface` | DNS / mail surface (MX, SPF, DMARC, DKIM, autodiscover) |
| 35 | `dns_intel` | Deep DNS intel (TXT mining, DKIM brute, SRV, CAA, DNSSEC, MTA-STS) |
| 36 | `subdomain_takeover` | Microsoft-specific subdomain takeover hunter |
| 37 | `http_headers` | HSTS / CSP / XFO / COOP / COEP roll-up + info-leak detection |
| 41 | `microsoft_endpoint` | Tunnel, Edge for Business, Endpoint Manager, Defender APIs, TVM |

## Power Platform & Dynamics

| # | Phase | Description |
|---|---|---|
| 11 | `copilot` | M365 Copilot + Copilot Studio detection |
| 12 | `power_platform` | Power Pages + OData leak, Dynamics 365 multi-region + sovereign |
| 50 | `power_pages_odata_deep` | Specific Dataverse entity-set anonymous-read probes |

## OSINT & Intel

| # | Phase | Description |
|---|---|---|
| 10 | `bing_dorks` | Microsoft-specific Bing dork pack |
| 18 | `github_dorks` | GitHub code-search dork pack (auto-execute with GITHUB_TOKEN) |
| 24 | `wayback` | Archive.org CDX historical sweep |
| 28 | `cert_san` | crt.sh CT-log SAN sweep for related hostnames |
| 47 | `breach_intel` | HIBP + paste-site dork pack |
| 48 | `webhook_hunt` | Teams + Outlook + Logic Apps + Functions + Slack/Discord webhook leak hunt |

## Internal Mode

| # | Phase | Description |
|---|---|---|
| `internal` | `internal_mode` | Internal-mode probes (assume corp-net foothold) |

See `entrascout --list-phases` for the full numbered list.
