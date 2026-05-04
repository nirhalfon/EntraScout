# EntraScout

**The most comprehensive single-shot Microsoft 365 / Entra ID / Azure unauth recon tool.**

Hand it a domain. It maps the entire Microsoft cloud footprint. Then tells you how an attacker would chain it.

!!! info "Version"
    Current version: **0.1.8**

## In 30 seconds

```bash
pip install entrascout
entrascout target.com
```

Output:

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

## What it covers

- **52 phases** · 250+ checks · attack-chain mapping · web console
- Executive PDF reports · authenticated Graph mode
- Unauthenticated external recon + internal-mode probes

## Modes

| Mode | Use case |
|---|---|
| **CLI** | Terminal-based scanning, automation, CI/CD |
| **Web Console** | Browser-based recon dashboard — 5 views (Console, Findings, Attack Chains, Surface, History) with live SSE streaming |

## Links

- [Quick Start](quickstart.md)
- [CLI Reference](cli-reference.md)
- [Web App Guide](web-app.md)
- [Phase Reference](phases.md)
- [GitHub](https://github.com/assor17/entrascout)
