<div align="center">

# 🛰️ EntraScout

### **The most comprehensive single-shot Microsoft 365 / Entra ID / Azure unauth recon tool.**

*Hand it a domain. It maps the entire Microsoft cloud footprint. Then tells you how an attacker would chain it.*

[![status](https://img.shields.io/badge/status-private%20alpha-orange?style=for-the-badge)](#)
[![python](https://img.shields.io/badge/python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](#)
[![license](https://img.shields.io/badge/license-MIT-informational?style=for-the-badge)](#)
[![scope](https://img.shields.io/badge/scope-authorized_only-red?style=for-the-badge)](#)
[![phases](https://img.shields.io/badge/phases-52-blueviolet?style=for-the-badge)](#)
[![version](https://img.shields.io/badge/version-0.1.8-success?style=for-the-badge)](#)

🎯 **52 phases · 250+ checks · attack-chain mapping · executive PDF reports · authenticated Graph mode**

</div>

---

## 🪄 In 30 seconds

```bash
$ entrascout target.com
```

```text
🛰  EntraScout v0.1.8 — recon target: target.com

[ phase  1] tenant            ✓ tenant_id 8efe2cef-... · region NAM
[ phase  2] federation        ✓ Federated · ADFS at corp.sts.target.com
[ phase 29] sharepoint_recon  ✓ 5 site collections enumerable
[ phase 31] mfa_gaps          ⚠ EWS basic-auth surface present  ·  ROPC enabled
[ phase 35] dns_intel         ✓ SaaS inventory: 11 providers   ·  4 DKIM selectors active
[ phase 36] subdomain_takeover⚠ takeover candidate: cdn.target.com → dangling .azurefd.net
[ phase 50] power_pages_odata ⚠ /_odata/contacts returns 200 anonymously

═══════════════════════════════════════════════════════════════
  HIGH    ADFS Relying Party catalog leaked at corp.sts.target.com (225 RPs)
  HIGH    ClaimsXray debug RP registered in production
  HIGH    Subdomain takeover candidate — cdn.target.com → dangling .azurefd.net
  MEDIUM  DKIM selectors reveal 4 ESP partners (Mailchimp, SendGrid, Marketo)
  MEDIUM  EXO basic-auth surface present (EWS, ActiveSync)
═══════════════════════════════════════════════════════════════

📊 Output: ./output/run_20260504_113212/
  ├─ executive_summary.html  ← 1-page PDF-ready audit deliverable
  ├─ report.html             ← full interactive report
  ├─ attack_paths.md         ← top attack chains in plain English
  ├─ findings.json           ← machine-readable
  └─ raw/                    ← preserved evidence
```

That's it. One command. One target. The full surface.

---

## 🤔 Why does this exist?

You point EntraScout at one domain and it gives you a complete, evidence-backed view of the org's Microsoft cloud footprint in a single command — every surface enumerated, every misconfiguration flagged with **impact text and recommended fix**, the strongest attack paths chained automatically with MITRE ATT&CK references.

It's purpose-built for the unauthenticated half of the engagement: external recon for red-team, audit, OSINT, and bug-bounty work. With `--token` it also runs an authenticated Graph pass for MFA-coverage / CA-policy / role-membership reporting.

The output is meant to be useful to humans — not a pile of JSON. Reports are interactive (filterable, collapsible, searchable), include impact explanations and remediation guidance, and ship with a print-ready 1-page executive summary.

---

## 🎯 What it covers

EntraScout runs **52 phases** across the entire Microsoft cloud surface. Click to expand each section.

<details>
<summary><strong>🆔 Identity & Federation</strong> — tenant fingerprint, ADFS deep, B2C, Verified ID, Workload Identities</summary>

- Tenant fingerprinting (tenant ID, region, cloud, custom branding)
- Federation type detection (Managed / Federated / B2C / External ID)
- **ADFS**: MEX exposure, IdP-Initiated Signon page, Relying Party catalog leak (the *389-RP NASA / 225-RP Ford / 1,266-RP Samsung* finding pattern), ClaimsXray-in-prod detection, Federation Metadata
- Microsoft Entra B2C tenants (`*.b2clogin.com`)
- Microsoft Entra External ID (`*.ciamlogin.com`)
- Microsoft Entra Verified ID (DID issuer URLs)
- Microsoft Entra Workload Identities
- Microsoft Entra ID Governance / Permissions Mgmt / Internet+Private Access (ZTNA)
- PIM admin deep-link
- Cross-tenant guest / B2B inference baseline

</details>

<details>
<summary><strong>👥 User & Service Enumeration</strong> — GetCredentialType, OneDrive timing, Teams, FOCI clients</summary>

- GetCredentialType silent enum
- OneDrive timing channel
- Teams external search
- Cross-validated user list with N-plus indicator
- FOCI (Family of Client IDs) probing
- AAD App Registration enumeration (AADSTS error-code differential)
- Graph metadata reachability + WWW-Authenticate parsing

</details>

<details>
<summary><strong>📧 M365 Office Apps</strong> — SharePoint, OneDrive, Exchange, Teams, Bookings, Forms, Stream, Loop, Whiteboard, Sway, Visio, Project, Planner, To-Do, Customer Voice, OneNote, Lists, Clipchamp</summary>

- **SharePoint deep recon**: site-collection wordlist, REST `/_api/web` probing, **anonymous search-API test**, legacy `/_vti_bin/`, admin tenant URL
- OneDrive / SharePoint anonymous-link dorks
- Exchange Online (OWA / ECP / EWS / ActiveSync / MAPI / OAB / PowerShell-LiveID)
- Teams (Live Events, Webinars, **Teams incoming-webhook hunt** — anonymous post-to-channel exec primitive)
- Bookings + **Bookings With Me** (free PII leak per-user)
- Forms, Stream, Loop, Whiteboard, Sway, Visio, Project, Planner, To-Do, Customer Voice
- OneNote shared notebooks, Office Online, Microsoft Lists, Clipchamp, Editor

</details>

<details>
<summary><strong>☁️ Azure Compute & Containers</strong> — App Service, Functions, AKS, Service Fabric, Container Apps, ACI, Spring Apps, Lab Services</summary>

- App Service + Kudu unauth detection
- **Function App `/api/{name}` brute force** — anon-callable functions = HIGH issue
- App Service deployment slots (`*-staging`, `*-dev`, `*-uat`)
- Static Web Apps + preview-branch deployments
- **AKS public API server** + anonymous `/healthz` probe
- Azure Service Fabric Explorer (port 19080)
- Azure Container Apps + Container Instances (ACI)
- Azure Spring Apps + Lab Services
- Azure Batch accounts

</details>

<details>
<summary><strong>💾 Azure Data, Storage & AI</strong> — Blob (with attribution!), Cosmos, SQL, Synapse, Data Factory, Databricks, AML, OpenAI, Cognitive, Health Bot</summary>

- **Azure Blob deep enum** with brand-attribution scoring (NO false-positives like other tools)
- Anonymous container listing + sensitive-file flagging
- Bundled **`blobexplorer`** CLI + **`blobweb`** local UI for inspecting findings
- Cosmos DB / SQL / Redis / Data Lake / Cognitive Search
- Synapse Studio + SQL endpoint
- Data Factory, HDInsight, **Azure Machine Learning workspaces**
- **Azure OpenAI** (`*.openai.azure.com`) + Cognitive Services
- Azure AI Foundry deep-link
- Azure API for FHIR (healthcare)
- Azure Health Bot, Confidential Ledger
- Container Registry (anonymous repo enum)

</details>

<details>
<summary><strong>🔌 Azure Networking & Integration</strong> — Logic Apps, Service Bus, Event Grid, SignalR, Web PubSub, Bastion, Private Link DNS leak</summary>

- **Logic App / Power Automate trigger URL hunt-pack** (leaked SAS-bound URLs = remote-exec primitive)
- Service Bus, Event Grid, Event Hubs, IoT Hub, Notification Hubs, Relay
- API Management
- Azure SignalR + Web PubSub
- Azure Bastion (`*.bastion.azure.com`)
- **Azure Private Link DNS leak detection** (`privatelink.*` records in public DNS)
- Communication Services
- Azure Front Door + CDN

</details>

<details>
<summary><strong>🛡️ Defender / Security / Compliance</strong> — Defender for Cloud / Endpoint / Identity / XDR, MCAS, Sentinel, Purview, IRM</summary>

- Microsoft Defender for Cloud (formerly ASC)
- Microsoft Defender for Endpoint API surface
- Microsoft Defender for Identity (`*.atp.azure.com`)
- Microsoft Defender XDR portal deep-link
- Microsoft Defender Vulnerability Management (TVM)
- MCAS / Defender for Cloud Apps regional portals
- Microsoft Sentinel SOAR webhook hunt-pack
- Microsoft Purview Compliance Manager + Insider Risk Management deep-link
- MIP (Microsoft Information Protection) sensitivity-label hunting

</details>

<details>
<summary><strong>⚡ Power Platform & Dynamics</strong> — Power Pages (with OData entity probes!), Power Apps, Power Automate, Dynamics 365 multi-region + sovereign clouds</summary>

- **Power Pages OData entity-set probe** — direct queries of `/contacts`, `/accounts`, `/incidents`, etc. (HIGH when 200 anonymously)
- Power Pages portal + custom-domain CNAME chase (vanity-domain detection)
- **D365 CRM Web API direct probe** (`/api/data/v9.2/` → 200 anonymously = HIGH)
- Dynamics 365 multi-region + sovereign clouds (GCC / GCC High / China / DoD)
- Power Apps public-play / iframe embed
- Power Automate + Logic App trigger hunt
- Power Virtual Agents / Copilot Studio bot enum
- Microsoft AppSource publisher pages
- Power Platform admin deep-links

</details>

<details>
<summary><strong>🌐 DNS Intelligence</strong> — TXT verification mining, DKIM brute, SRV, CAA, DNSSEC, MTA-STS, TLS-RPT, BIMI</summary>

- **TXT verification mining** — SaaS supply-chain map: Atlassian, Salesforce, Marketo, Mailchimp, SendGrid, Pardot, Slack, Zoom, Box, Dropbox, GitHub, Adobe, Apple, Datadog, Asana, Intercom, ProofPoint, Mimecast, Barracuda + 15 more providers
- **DKIM selector brute** (~30 selectors) — reveals mail-flow architecture
- SRV records (autodiscover, MSOID, Kerberos, LDAP, GC, SIP, XMPP)
- CAA records (cert-mgmt posture)
- DNSSEC / DNSKEY / DS chain
- MTA-STS, TLS-RPT, BIMI

</details>

<details>
<summary><strong>🚪 Subdomain Takeover Hunter</strong> — Microsoft-specific dangling-resource patterns</summary>

CNAME chain inspection for:
- `cloudapp.azure.com` (Cloud Service)
- `azurewebsites.net` (App Service)
- `trafficmanager.net` (Traffic Manager)
- `azurefd.net` (Front Door)
- `azurestaticapps.net` (Static Web App)
- `blob.core.windows.net` (Storage)
- `search.windows.net` (Cognitive Search)
- `azure-api.net` (APIM)
- `azurecontainer.io` (ACI)

Reports HIGH severity when target is dangling (NXDOMAIN / 404 fingerprint).

</details>

<details>
<summary><strong>🔐 MFA Gap Mapper</strong> — surfaces that bypass MFA</summary>

- EXO legacy auth: EWS, ActiveSync, Autodiscover, OAB, MAPI, PowerShell-LiveID
- ADFS WS-Trust `/usernamemixed` (2005 + 1.3) — silent username-enum
- ADFS `/windowstransport` (Kerberos, often MFA-exempt)
- AAD ROPC token flows (always MFA-skip by design)
- **Authenticated mode**: parse `/reports/authenticationMethods/userRegistrationDetails` to flag admins without MFA registered

</details>

<details>
<summary><strong>🍯 Dark Corners</strong> — niche Microsoft surfaces</summary>

Microsoft Sway · Visio for the Web · Project for the Web · Planner · To Do · Whiteboard · **Bookings With Me** · Customer Voice · Power Apps public play · Defender for Identity · Defender XDR · Microsoft Purview · Microsoft Viva · Microsoft 365 Lighthouse (MSP) · Microsoft Loop · Microsoft Editor · Microsoft Search · Bing for Business · Microsoft Lists · Microsoft Tunnel · Microsoft Edge for Business · Windows Autopilot · Microsoft Endpoint Manager · 30+ tenant deep-links

</details>

<details>
<summary><strong>🔗 Cross-SaaS & OSINT</strong> — supply-chain inventory beyond Microsoft</summary>

- Atlassian (`*.atlassian.net`) · Slack · Zoom · Webex · GitLab · GitHub orgs · Bitbucket · HuggingFace · Notion · Cloudflare Pages/Workers · Vercel · Netlify · Heroku · **AWS S3 cross-cloud audit**
- **GitHub code-search dork pack** (auto-execute with `GITHUB_TOKEN`)
- **NPM / PyPI / Docker Hub** package-leak hunting
- **HaveIBeenPwned** breach indicator (with `HIBP_API_KEY`)
- **Wayback / archive.org** historical sweep
- **crt.sh CT-log SAN sweep** for additional brand hostnames
- **Webhook leak hunt-pack** — Teams + Outlook + Logic Apps + Functions + Slack + Discord
- **Azure subscription ID leak hunt-pack**

</details>

<details>
<summary><strong>🎯 Attack-Chain Mapping (the differentiator)</strong></summary>

Every finding is tagged with what it *enables*. The runner pattern-matches tags against attack-path templates and outputs the top paths in plain English with MITRE ATT&CK technique IDs:

```text
1. Spoof-domain phishing chain
   Effort: low  ·  Blast radius: credential theft, account takeover
   Triggers: DNS-DMARC-MISSING, USER-ENUM-GETCREDTYPE
   - DMARC missing
   - Valid user list harvested
   → send spoofed mail from target.com → harvest creds → MFA fatigue or device-code phish.

2. Golden SAML via on-prem ADFS
   Effort: high  ·  Blast radius: tenant-wide impersonation
   Triggers: FED-ADFS-DETECTED, FED-ADFS-MEX-EXPOSED, ADFS-CLAIMSXRAY-IN-PROD
   - ADFS detected at corp.sts.target.com
   - 225 Relying Parties enumerated, including AWS-federated apps and SAP BTP
   - ClaimsXray debug RP in production aids claim-schema discovery
   → on-prem foothold → exfil token-signing cert → forge SAML for any of 225 RPs (T1606.002)
```

The HTML report includes a Mermaid graph; `attack_paths.md` is paste-ready for engagement reports.

</details>

<details>
<summary><strong>📊 Executive Summary (PDF-ready)</strong></summary>

EntraScout generates a **1-page printable executive summary** alongside every scan:
- Top critical & high findings table
- Tenant fingerprint at-a-glance
- Top 5 attack paths
- Defense posture roll-up
- Audit-deliverable styled

Open `executive_summary.html` in a browser → **Print → Save as PDF**. Done.

No extra dependencies (no weasyprint / wkhtmltopdf required).

</details>

---

## 🚀 Quick start

```bash
git clone https://github.com/osherassor/EntraScout.git
cd EntraScout
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Run
entrascout target.com

# With internal-mode probes (assume corp-net foothold)
entrascout target.com --internal --user ceo@target.com

# Stealth mode (low QPS + jitter + MS-plausible UA)
entrascout target.com --stealth

# See all phases (numbers, names, descriptions)
entrascout --list-phases

# Run only specific phases (numbers OR names — both work)
entrascout target.com --phases 1,2,29,31,35,36
entrascout target.com --phases tenant,federation,sharepoint_recon,mfa_gaps

# Authenticated Graph mode (MFA-registration report, CA dump, SPs)
GRAPH_TOKEN=eyJ0eXAi... entrascout target.com --token "$GRAPH_TOKEN"

# Auto-execute GitHub code-search dorks
GITHUB_TOKEN=ghp_... entrascout target.com

# HaveIBeenPwned domain-breach lookup
HIBP_API_KEY=... entrascout target.com
```

### Common flags

| Flag | Purpose |
|---|---|
| `--internal` | Add internal-mode probes (ADFS server discovery, Exchange on-prem, AAD Connect) |
| `--user EMAIL` | Seed user enumeration (e.g. `ceo@target.com`) |
| `--token JWT` | Graph token for authenticated phase 34 (CA dump, MFA registration report) |
| `--bing-key KEY` | Auto-execute Microsoft-specific Bing dorks |
| `--quick` | Faster scan; reduced coverage |
| `--stealth` | Low QPS + jitter + rotating MS UAs |
| `--phases LIST` | Phase numbers OR names (e.g. `1,2,29` or `tenant,federation`) |
| `--list-phases` | Print all phases (numbers + names + descriptions) and exit |
| `--workers N` | Concurrency (default 32) |
| `--timeout SECS` | Per-request timeout (default 8) |

### Phase reference

Run `entrascout --list-phases` for the live table from your installed version. Quick reference:

| # | Name | What it covers |
|---:|---|---|
| 1 | tenant | Tenant fingerprint (ID, region, cloud, branding) |
| 2 | federation | Federation type + ADFS deep (MEX, RP catalog, ClaimsXray) |
| 3 | user_enum | User enumeration (GetCredentialType, OneDrive timing, Teams) |
| 4 | m365_services | M365 service surface (SP, OneDrive, Exchange, Teams) |
| 5 | dns_surface | DNS / mail surface (MX, SPF, DMARC, DKIM, autodiscover) |
| 6 | auth_surface | Auth attack surface (legacy banners, ROPC, AADSTS) |
| 7 | oauth | Token / OAuth (FOCI, device-code surface) |
| 8 | defense_posture | Defense roll-up (mail spoofing, legacy auth, ADFS) |
| 9 | tenant_linkage | Sibling domains in same tenant |
| 10 | bing_dorks | Microsoft-specific Bing dork pack |
| 11 | copilot | M365 Copilot + Copilot Studio detection |
| 12 | power_platform | Power Pages + OData leak, Dynamics 365 multi-region |
| 13 | azure_resources | App Service, Kudu, Storage, ACR, SWA, Front Door, etc. |
| 14 | identity_edges | App Proxy, Defender for Cloud Apps, DRS endpoints |
| 15 | ms_public_content | Bookings, Forms, Stream, Loop, Power BI public, Yammer |
| 16 | azure_subdomain_enum | Key Vault, OpenAI, Cognitive, App Service slots |
| 17 | aad_apps | App Registration enum, B2C tenant, Graph metadata |
| 18 | github_dorks | GitHub code-search dork pack (auto-runs with `GITHUB_TOKEN`) |
| 19 | logic_apps | Logic App / Power Automate trigger URL hunt |
| 20 | ado_deep | ADO deeper (legacy visualstudio.com, marketplace, pipelines) |
| 21 | onedrive_links | OneDrive / SharePoint anonymous-link dorks |
| 22 | intune | Intune / MDM endpoints |
| 23 | guest_inference | Cross-tenant B2B / guest signaling baseline |
| 24 | wayback | Archive.org CDX historical sweep |
| 25 | tenant_directory | Sibling domains in *different* tenants |
| 26 | defender_posture | Defender / MCAS / Sentinel / SOAR / MIP roll-up |
| 27 | package_leaks | NPM scope, PyPI prefix, Docker Hub namespace |
| 28 | cert_san | crt.sh CT-log SAN sweep |
| 29 | sharepoint_recon | SharePoint deep (site enum, REST API, anon search-API) |
| 30 | azure_data_services | Cosmos / SQL / Redis / Data Lake / Event Grid / IoT / SB |
| 31 | mfa_gaps | MFA-bypass surface mapper (EXO basic, ADFS WS-Trust, ROPC) |
| 32 | functions_unauth | Azure Function App `/api/{name}` brute force |
| 33 | dark_corners | Niche MS surfaces (Sway, Visio, Project, Bookings With Me) |
| 34 | authenticated | Authenticated Graph mode (`--token` required) |
| 35 | dns_intel | TXT mining, DKIM brute, SRV, CAA, DNSSEC, MTA-STS, BIMI |
| 36 | subdomain_takeover | Microsoft-specific subdomain TKO hunter |
| 37 | http_headers | HSTS / CSP / XFO / COOP / COEP roll-up |
| 38 | azure_compute_extras | AKS, Service Fabric, Batch, Spring Apps, Lab Services |
| 39 | azure_data_extras | Synapse, Data Factory, Databricks, HDInsight, AML, FHIR |
| 40 | azure_network_extras | SignalR, Web PubSub, Bastion, Private Link DNS leak |
| 41 | microsoft_endpoint | Tunnel, Edge for Business, Endpoint Manager, MDE, TVM |
| 42 | dynamics_deep | D365 CRM Web API, Power Pages vanity domains, AppSource |
| 43 | entra_advanced | External ID, Verified ID, Workload, Governance, ZTNA, PIM |
| 44 | teams_deep | Teams Live Events / Webinars + webhook hunt + Phone System |
| 45 | office_extras | OneNote, Office Online, Lists consumer, Clipchamp |
| 46 | cross_saas | 15 cross-SaaS tenant probes (Atlassian/Slack/Zoom/etc.) |
| 47 | breach_intel | HIBP + paste-site dork pack |
| 48 | webhook_hunt | Teams + Outlook + Logic Apps + Functions webhook leak hunt |
| 49 | subscription_leak | Azure subscription ID leak hunt-pack + GUID extraction |
| 50 | power_pages_odata_deep | Specific Dataverse entity-set anon-read probes |
| 51 | final_gaps | Service Fabric, ACI, VPN/ER, Relay, NH, Stream Analytics |
| `internal` | internal_mode | Internal-network probes (use with `--internal`) |

---

## 📦 Output

Every run writes a self-contained directory:

| File | What |
|---|---|
| 📄 `executive_summary.html` | **1-page printable PDF-ready audit deliverable** |
| 📊 `report.html` | Full interactive HTML report (Mermaid attack-graph included) |
| 🧠 `attack_paths.md` | Top attack chains in plain English with MITRE ATT&CK IDs |
| 🚨 `issues.json` | Security issues only |
| 🎯 `leads.json` | Next-step opportunities |
| 📋 `findings.json` | All findings (machine-readable) |
| ✅ `validations.json` | Reachability confirmations |
| 🩹 `recommendations.md` | Hardening recommendations per issue |
| 📜 `history.jsonl` | **Every** HTTP probe (URL, method, status, headers, ms) — full audit trail |
| 📂 `raw/` | Preserved raw responses (OIDC config, ADFS MEX, SP HTML, etc.) — evidence for reports |
| 📒 `entrascout.log` | Full debug log |

**No masking. Pure data.** Findings, leads, issues, recommendations — all separated, all linked.

---

## 🧰 Bundled tools

The `tools/` directory ships ad-hoc utilities that pair with EntraScout output:

| Tool | What it does |
|---|---|
| `tools/blobexplorer.py` | Anonymous Azure Blob Storage CLI: probe well-known containers, list blobs (with sensitive-name flagging), HEAD a blob, download with regex filter, run brand-attribution heuristics |
| `tools/blobweb.py` | Local Flask UI (port 5050) wrapping `blobexplorer`. Type a storage account / URL → click "Explore" → list, preview, download blobs from the browser. Read-only |

```bash
# CLI
python tools/blobexplorer.py dhsfiles
python tools/blobexplorer.py dhsfiles -c files --sensitive
python tools/blobexplorer.py dhsfiles --attribute dhs.gov

# Web UI
pip install flask
python tools/blobweb.py
# open http://127.0.0.1:5050
```

---

## 📚 Recipes — "How do I find X?"

<details>
<summary><strong>How do I find leaked Microsoft Teams webhooks for an org?</strong></summary>

```bash
entrascout target.com --phases 44,48
# Then inspect leads.json for `teams_webhook_hunt` and `webhook_url_hunt_pack`
# Use the GitHub dorks emitted there directly on github.com/search?type=code
```

</details>

<details>
<summary><strong>How do I find subdomain takeover candidates?</strong></summary>

```bash
entrascout target.com --phases 5,36
# Phase 36 (subdomain_takeover) chains the discovered DNS records against
# Microsoft-specific dangling-resource patterns. HIGH severity = takeover candidate.
```

</details>

<details>
<summary><strong>How do I map an org's full SaaS supply chain?</strong></summary>

```bash
entrascout target.com --phases 35,46
# Phase 35 (dns_intel) mines TXT verification + DKIM selectors
# Phase 46 (cross_saas) probes 15 third-party platforms for tenant existence
# `findings.json` includes a `saas_inventory_via_txt` finding with the full provider list
```

</details>

<details>
<summary><strong>How do I find ADFS attack-chain primitives for a target?</strong></summary>

```bash
entrascout target.com --phases 2,31
# Phase 2 (federation): ADFS detection + MEX/FederationMetadata + RP catalog
# Phase 31 (mfa_gaps): WS-Trust legacy endpoints (usernamemixed, windowstransport)
# Look for: adfs_relying_party_catalog_disclosed, adfs_claimsxray_in_production
```

</details>

<details>
<summary><strong>How do I QA my org's MFA coverage?</strong></summary>

```bash
# Authenticated mode — needs a Graph token with Reports.Read.All
GRAPH_TOKEN="eyJ..." entrascout target.com --phases 31,34 --token "$GRAPH_TOKEN"
# Phase 34 (authenticated) parses /reports/authenticationMethods/userRegistrationDetails
# Flags admins WITHOUT MFA registered as HIGH issues
```

</details>

<details>
<summary><strong>How do I find anonymous Power Pages OData data leaks?</strong></summary>

```bash
entrascout target.com --phases 12,50
# Phase 12 (power_platform): finds the portal + $metadata
# Phase 50 (power_pages_odata_deep): probes 25+ Dataverse entity sets
# HIGH issue when /_odata/contacts (or any common entity) returns 200 with data anonymously
```

</details>

---

## 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         entrascout target.com                        │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  RunContext      ◀── stealth / workers / token / bing-key     │
   │  StealthClient   ◀── rotating MS UAs · DNS+HTTP audit trail   │
   │  OutputManager   ◀── findings / raw / history / artifacts     │
   └──────────────────────────────────────────────────────────────┘
                                  │
              ┌───────────────────┴───────────────────┐
              ▼                                       ▼
   ┌──────────────────────┐               ┌──────────────────────┐
   │   52 phase modules   │               │   Cross-finding      │
   │  (pluggable, async)  │  ◀────────▶   │   tag system         │
   └──────────────────────┘               └──────────────────────┘
              │                                       │
              ▼                                       ▼
   ┌──────────────────────┐               ┌──────────────────────┐
   │  raw evidence files  │               │  attack_paths.md     │
   │  + history.jsonl     │               │  (MITRE-tagged       │
   │                      │               │   chain templates)   │
   └──────────────────────┘               └──────────────────────┘
              │                                       │
              └───────────────────┬───────────────────┘
                                  ▼
              ┌──────────────────────────────────────┐
              │  report.html  +  executive_summary  │
              │  (Mermaid graph + 1-page PDF)       │
              └──────────────────────────────────────┘
```

Every phase is an `async def run(ctx, http, snapshot, om) -> list[Finding]` — drop-in pluggable. Tag-driven attack-chain logic is content-addressable so adding a tag automatically updates the chain templates.

---

## 🥷 Stealth

`--stealth` enables:
- 🐢 Low QPS (default 3/s)
- 🎲 Random jitter
- 🪪 Rotating MS-client User-Agents (Outlook, Teams desktop, Edge, Outlook iOS)
- 🧅 Optional SOCKS chain via `--proxy`

Even without `--stealth`, EntraScout uses MS-plausible UAs and never sets `User-Agent: python-httpx/0.27`.

---

## 🗺️ Roadmap

Currently in **private alpha** (v0.1.x). Path to public release:

- [x] 52 phases covering full M365 / Entra / Azure / cross-SaaS surface
- [x] Attack-chain mapping with MITRE ATT&CK references
- [x] Interactive HTML report (filterable, collapsible, with impact + recommendations)
- [x] 1-page executive PDF-ready summary
- [x] Authenticated Graph mode (`--token`)
- [x] Bundled blob explorer (CLI + local web UI)
- [x] QA hardening on real bug-bounty targets (Ford / Visa / Hyatt / others)
- [ ] Public release as v0.2.0
- [ ] Profile presets (`--profile fast / standard / deep`)
- [ ] Snapshot diffing (`entrascout diff old.json new.json`)
- [ ] Continuous-monitoring mode (`--watch --interval 1d`)

---

## ⚖️ Authorized use only

EntraScout is for **authorized** security testing — pentest engagements, your own assets, programs you're enrolled in. Don't probe organizations you don't have permission to test. Microsoft cloud probes are logged at the tenant level and visible to security teams.

---

## 📜 License

MIT (locked at public release).

---

## 👤 Author

Built by [Osher Assor](https://github.com/osherassor).

If EntraScout helped you find something, drop a ⭐ on the repo.
