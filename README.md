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

📖 [Full Documentation](https://entrascout.readthedocs.io)

</div>

---

## 🪄 In 30 seconds

```bash
$ pip install entrascout
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

---

## 🚀 Quick Start

```bash
# Install
pip install entrascout

# First scan
entrascout target.com

# Web console (terminal-style recon dashboard)
docker-compose up --build
# → http://localhost:8000
```

## 📖 Documentation

Full docs are hosted on **ReadTheDocs**:

👉 **[entrascout.readthedocs.io](https://entrascout.readthedocs.io)**

- [Quick Start](https://entrascout.readthedocs.io/quickstart/)
- [CLI Reference](https://entrascout.readthedocs.io/cli-reference/)
- [Phase Reference](https://entrascout.readthedocs.io/phases/)
- [Web App](https://entrascout.readthedocs.io/web-app/)
- [API Reference](https://entrascout.readthedocs.io/api/)
- [Architecture](https://entrascout.readthedocs.io/architecture/)
- [Recipes](https://entrascout.readthedocs.io/recipes/)
- [Deployment](https://entrascout.readthedocs.io/deployment/)
- [Contributing](https://entrascout.readthedocs.io/contributing/)

## 🎯 What it covers

Click to expand each section in the [Phase Reference](https://entrascout.readthedocs.io/phases/).

- Identity & Federation (tenant, ADFS, B2C, Verified ID, Workload Identities)
- M365 Services (Exchange, SharePoint, Teams, OneDrive, Yammer, Copilot)
- Azure Resources (App Service, Storage, Functions, Kudu, Container Registry, Front Door)
- Auth & MFA (legacy auth, ROPC, device-code, AADSTS error analysis)
- DNS & Network (MX, SPF, DMARC, DKIM, subdomain takeover, headers)
- Power Platform & Dynamics (Power Pages, Dataverse, OData leaks)
- OSINT & Intel (Bing dorks, GitHub dorks, breach intel, webhook hunt)

## 🛡️ Authorized testing only

EntraScout is purpose-built for **authorized** security assessments: red team, pentest, audit, bug bounty, and OSINT research.

Only run it against domains you own or have explicit written permission to test.

## 📦 Output artifacts

| File | Purpose |
|---|---|
| `report.html` | Full interactive dark-mode report |
| `executive_summary.html` | 1-page print/PDF-ready summary |
| `findings.json` | Machine-readable findings |
| `chain.json` | Attack-chain graph data |
| `attack_paths.md` | Top attack chains with MITRE references |
| `recommendations.md` | Remediation guidance |
| `tenant.json` | Tenant fingerprint |
| `raw/` | Preserved evidence |

## 🔗 Links

- [Documentation](https://entrascout.readthedocs.io)
- [Changelog](https://entrascout.readthedocs.io)
- [Issue Tracker](https://github.com/assor17/entrascout/issues)

## 📜 License

MIT — see [LICENSE](LICENSE).
