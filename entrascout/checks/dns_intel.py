"""Phase 35 — Deep DNS intelligence mining.

Goes beyond MX/SPF/DMARC/DKIM (already in dns_surface) to extract:

- TXT verification mining (SaaS supply-chain map): atlassian, salesforce,
  marketo, mailchimp, sendgrid, pardot, slack-verification, google-site-verif,
  facebook-domain-verification, amazonses, github-pages, segment, hubspot,
  stripe, _acme-challenge, etc.
- SRV records (SfB, autodiscover, MSOID, kerberos, ldap, gc)
- CAA records (cert-mgmt posture)
- DNSSEC / DANE indicators
- MTA-STS (`_mta-sts.{domain}`), TLS-RPT (`_smtp._tls.{domain}`), BIMI (`default._bimi.{domain}`)
- DKIM selector brute (~30 known selectors)
"""
from __future__ import annotations

import asyncio

from ..dns_client import query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, issue, validation


# Known TXT-verification record names → SaaS provider mapping
# Format: (txt_record_prefix_or_name, provider_label, content_signal_substring_optional)
TXT_VERIFICATION_PATTERNS = [
    # Atlassian (Confluence, Jira, Trello)
    ("atlassian-domain-verification", "Atlassian (Confluence/Jira)", None),
    # Google
    ("google-site-verification", "Google (Workspace / Search Console)", None),
    # Microsoft (we already detect MS but flag the verification too)
    ("MS=", "Microsoft 365 / Azure (TXT verification)", None),
    # Salesforce
    ("salesforce", "Salesforce", None),
    # Marketo
    ("marketo", "Marketo", None),
    # Mailchimp
    ("mailchimp", "Mailchimp", None),
    # SendGrid
    ("sendgrid", "SendGrid (Twilio)", None),
    # Pardot
    ("pardot", "Pardot (Salesforce)", None),
    # HubSpot
    ("hubspot", "HubSpot", None),
    # Stripe
    ("stripe-verification", "Stripe", None),
    # Slack
    ("slack-verification", "Slack", None),
    # Zoom
    ("ZOOM_verify_", "Zoom", None),
    # Box
    ("box-verification", "Box", None),
    # Dropbox
    ("dropbox-domain-verification", "Dropbox", None),
    # Notion
    ("notion-domain-verification", "Notion", None),
    # Facebook
    ("facebook-domain-verification", "Meta / Facebook", None),
    # Apple
    ("apple-domain-verification", "Apple", None),
    # Adobe
    ("adobe-idp-site-verification", "Adobe IdP", None),
    # Amazon
    ("amazonses", "Amazon SES", None),
    # GitHub
    ("github-verification", "GitHub", None),
    # GitLab
    ("gitlab-verification", "GitLab", None),
    # Segment
    ("segment-site-verification", "Segment / Twilio", None),
    # ProofPoint / Mimecast / Barracuda (security gateways often use TXT)
    ("proofpoint", "Proofpoint", None),
    ("mimecast", "Mimecast", None),
    ("barracuda", "Barracuda", None),
    # Datadog
    ("dd-verification", "Datadog", None),
    # Asana
    ("asana-verification", "Asana", None),
    # Intercom
    ("intercom-verification", "Intercom", None),
    # Webex
    ("cisco-ci-domain-verification", "Cisco / Webex", None),
    # Pendo
    ("pendo-verification", "Pendo", None),
    # ACME / Let's Encrypt
    ("_acme-challenge", "ACME / Let's Encrypt validation", None),
]


# DKIM selectors to brute force (organized by likely provider)
DKIM_SELECTORS = [
    # Microsoft 365 (Exchange Online)
    "selector1", "selector2",
    # Google Workspace
    "google",
    # SendGrid
    "s1", "s2",
    # Mailchimp
    "k1", "k2", "k3",
    # Marketo
    "m1", "marketo",
    # Pardot
    "pardot1", "pardot2", "pf",
    # Mandrill
    "mandrill",
    # SendinBlue / Brevo
    "sendinblue",
    # Mailgun
    "mailgun",
    "mta",
    # ZeptoMail / Zoho
    "zoho",
    # Postmark
    "postmark",
    "20210112",
    # ProofPoint
    "proofpoint",
    # Mimecast
    "mimecast",
    # Common defaults
    "default", "dkim", "mail", "key1", "key2",
    # Custom-named (sometimes leak app names)
    "main", "smtp", "outbound",
    # Date-format selectors
    "20231201", "202401", "2024",
]


# SRV records relevant for AD / M365 hybrid posture
SRV_RECORDS = [
    ("_autodiscover._tcp", "Exchange Autodiscover SRV"),
    ("_msoid._tcp", "M365 / WIA (legacy)"),
    ("_kerberos._tcp", "Kerberos (rare on public DNS — leak indicator)"),
    ("_ldap._tcp", "LDAP (rare on public DNS — leak indicator)"),
    ("_gc._tcp", "Global Catalog (rare on public DNS — leak indicator)"),
    ("_sip._tcp", "SIP / Lync"),
    ("_sip._tls", "SIP TLS / Lync"),
    ("_sipfederationtls._tcp", "SfB / Lync federation"),
    ("_xmpp-client._tcp", "XMPP client"),
    ("_xmpp-server._tcp", "XMPP server federation"),
    ("_caldav._tcp", "CalDAV"),
    ("_imap._tcp", "IMAP"),
    ("_pop3._tcp", "POP3"),
    ("_submission._tcp", "Mail submission (587)"),
    ("_smtp._tcp", "SMTP"),
]


async def safe_query(name: str, rtype: str, timeout: float = 5.0) -> list[str]:
    try:
        return await query(name, rtype, timeout=timeout)
    except Exception:
        return []


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    domain = (snap.primary_domain or ctx.target).lower()

    # ---- 1. TXT verification mining ----
    txt_records = await safe_query(domain, "TXT")
    saas_inventory: list[dict] = []

    for prefix, label, _ in TXT_VERIFICATION_PATTERNS:
        matched = [t for t in txt_records if prefix.lower() in t.lower()]
        if matched:
            saas_inventory.append({"provider": label, "prefix": prefix,
                                    "sample_records": [m[:200] for m in matched[:3]]})

    if saas_inventory:
        findings.append(lead(
            phase="dns_intel", check="saas_inventory_via_txt",
            title=f"SaaS inventory via TXT verification: {len(saas_inventory)} providers",
            target=domain, severity=Severity.LOW, confidence=Confidence.HIGH,
            description=(
                "TXT verification records reveal the org's full SaaS supply chain. "
                "Each provider listed below is a confirmed third-party that the "
                "org has set up to send mail or verify ownership of this domain."
            ),
            data={"providers": saas_inventory, "count": len(saas_inventory)},
            recommendation=(
                "Audit which TXT verifications are still needed. Stale verifications "
                "from former vendors should be removed (reduces supply-chain attack surface)."
            ),
        ))

    # ---- 2. DKIM selector brute force ----
    sem = asyncio.Semaphore(min(ctx.workers, 8))

    async def probe_dkim(selector: str) -> tuple[str, str] | None:
        async with sem:
            r = await safe_query(f"{selector}._domainkey.{domain}", "TXT")
        if r:
            for rec in r:
                if "v=DKIM1" in rec or "k=rsa" in rec or "p=" in rec:
                    return selector, rec[:300]
        return None

    dkim_results = await asyncio.gather(*(probe_dkim(s) for s in DKIM_SELECTORS))
    valid = [r for r in dkim_results if r]
    if valid:
        provider_map = {
            "selector1": "Microsoft 365", "selector2": "Microsoft 365",
            "google": "Google Workspace",
            "k1": "Mailchimp", "k2": "Mailchimp", "k3": "Mailchimp",
            "m1": "Marketo", "marketo": "Marketo",
            "pf": "Pardot", "pardot1": "Pardot", "pardot2": "Pardot",
            "s1": "SendGrid", "s2": "SendGrid",
            "mandrill": "Mandrill", "sendinblue": "SendinBlue/Brevo",
            "mailgun": "Mailgun", "mta": "Mailgun",
            "zoho": "Zoho", "postmark": "Postmark",
            "proofpoint": "Proofpoint", "mimecast": "Mimecast",
        }
        senders: dict[str, list[str]] = {}
        for sel, _rec in valid:
            prov = provider_map.get(sel, "Custom / unknown")
            senders.setdefault(prov, []).append(sel)
        findings.append(lead(
            phase="dns_intel", check="dkim_selectors_active",
            title=f"DKIM selectors active: {len(valid)} (mail-flow architecture)",
            target=domain, severity=Severity.LOW, confidence=Confidence.HIGH,
            description=(
                "Active DKIM selectors reveal the org's mail-flow infrastructure: "
                "each selector pair is a third-party that signs mail on the org's "
                "behalf or an internal mail gateway. Combined with the TXT inventory "
                "this maps the full mail security architecture."
            ),
            data={"providers": senders, "active_selectors": [s for s, _ in valid]},
        ))

    # ---- 3. SRV records ----
    async def probe_srv(rec: str, label: str) -> None:
        results = await safe_query(f"{rec}.{domain}", "SRV")
        if results:
            findings.append(data(
                phase="dns_intel", check=f"srv_{rec.replace('.','_')}",
                title=f"SRV {rec}.{domain} — {label}",
                target=f"{rec}.{domain}", confidence=Confidence.HIGH,
                payload={"label": label, "records": results, "rtype": "SRV"},
            ))

    await asyncio.gather(*(probe_srv(r, l) for r, l in SRV_RECORDS))

    # ---- 4. CAA records ----
    caa = await safe_query(domain, "CAA")
    if caa:
        findings.append(data(
            phase="dns_intel", check="caa_records",
            title=f"CAA records on {domain} — {len(caa)} entries",
            target=domain, confidence=Confidence.HIGH,
            payload={"records": caa,
                     "interpretation": "CAA records restrict which CAs can issue certs. Audit-relevant for cert mgmt posture."},
        ))
    else:
        findings.append(data(
            phase="dns_intel", check="caa_records_missing",
            title=f"No CAA records on {domain} (any CA can issue)",
            target=domain, confidence=Confidence.HIGH,
            payload={"recommendation": "Consider adding CAA records to restrict cert issuance."},
        ))

    # ---- 5. DNSSEC ----
    dnssec_ds = await safe_query(domain, "DS")
    dnssec_dnskey = await safe_query(domain, "DNSKEY")
    findings.append(data(
        phase="dns_intel", check="dnssec_status",
        title=f"DNSSEC: DS records {len(dnssec_ds)}, DNSKEY records {len(dnssec_dnskey)}",
        target=domain, confidence=Confidence.HIGH,
        payload={"ds_count": len(dnssec_ds), "dnskey_count": len(dnssec_dnskey),
                 "signed": len(dnssec_dnskey) > 0,
                 "interpretation": "Domain is DNSSEC-signed" if dnssec_dnskey else "Domain has no DNSSEC chain"},
    ))

    # ---- 6. MTA-STS / TLS-RPT / BIMI ----
    mta_sts = await safe_query(f"_mta-sts.{domain}", "TXT")
    if mta_sts:
        findings.append(data(
            phase="dns_intel", check="mta_sts_present",
            title=f"MTA-STS configured on {domain}",
            target=f"_mta-sts.{domain}", confidence=Confidence.HIGH,
            payload={"records": mta_sts},
        ))

    tls_rpt = await safe_query(f"_smtp._tls.{domain}", "TXT")
    if tls_rpt:
        findings.append(data(
            phase="dns_intel", check="tls_rpt_present",
            title=f"TLS-RPT configured on {domain}",
            target=f"_smtp._tls.{domain}", confidence=Confidence.HIGH,
            payload={"records": tls_rpt},
        ))

    bimi = await safe_query(f"default._bimi.{domain}", "TXT")
    if bimi:
        findings.append(data(
            phase="dns_intel", check="bimi_present",
            title=f"BIMI logo configured on {domain}",
            target=f"default._bimi.{domain}", confidence=Confidence.HIGH,
            payload={"records": bimi},
        ))

    return findings
