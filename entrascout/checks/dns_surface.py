"""Phase 5 — DNS / mail surface (MX, SPF, DMARC, DKIM, M365 CNAMEs)."""
from __future__ import annotations

from ..dns_client import collect, parse_dmarc, parse_spf, query
from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, issue, validation


M365_MX_HINTS = ("mail.protection.outlook.com", "outlook.com")
M365_SPF_INCLUDES = ("spf.protection.outlook.com", "spfb.protection.outlook.com")
M365_AUTODISCOVER_TARGETS = ("autodiscover.outlook.com",)


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    domain = snap.primary_domain or ctx.target

    # ---- Apex MX / SPF / DMARC / DKIM ----
    apex = await collect(domain)
    om.save_raw(f"dns/apex_{domain}.json", str(apex))

    # Emit raw records as DATA findings (one per record, for CSV)
    for rtype, vals in apex.items():
        for v in vals:
            findings.append(data(
                phase="dns_surface", check=f"dns_{rtype.lower()}",
                title=f"{rtype} {domain}: {v}",
                target=domain, confidence=Confidence.HIGH,
                payload={"name": domain, "rtype": rtype, "value": v},
            ))

    # MX → Exchange Online?
    mx_vals = apex.get("MX", [])
    if any(M365_MX_HINTS[0] in m for m in mx_vals):
        findings.append(data(
            phase="dns_surface", check="mx_o365",
            title="MX confirms Exchange Online (mail.protection.outlook.com)",
            target=domain, confidence=Confidence.CONFIRMED,
            payload={"mx": mx_vals},
            tags=[ChainTag.DNS_MX_O365],
        ))

    # SPF parse
    spf = parse_spf(apex.get("TXT", []))
    if spf:
        is_o365 = any(any(h in inc for h in M365_SPF_INCLUDES) for inc in spf.get("includes", []))
        all_mark = (spf.get("all") or "").lower()
        if "-all" in all_mark:
            findings.append(validation(
                phase="dns_surface", check="spf_strict",
                title=f"SPF is strict (-all). Includes: {spf.get('includes')}",
                target=domain,
                payload={"raw": spf["raw"], "includes": spf["includes"], "all": spf["all"], "is_o365": is_o365},
                tags=[ChainTag.DNS_SPF_OK],
            ))
        elif "~all" in all_mark:
            findings.append(issue(
                phase="dns_surface", check="spf_softfail",
                title="SPF uses softfail (~all). Spoofed mail may still arrive.",
                target=domain, severity=Severity.LOW, confidence=Confidence.HIGH,
                description="SPF policy is permissive — recipients may treat unauthorized senders with leniency.",
                data={"raw": spf["raw"]},
                tags=[ChainTag.DNS_SPF_PERMISSIVE],
                recommendation="Move SPF from `~all` (softfail) to `-all` (hardfail) once mail flows are verified.",
            ))
        elif "+all" in all_mark or all_mark == "?all":
            findings.append(issue(
                phase="dns_surface", check="spf_pass_all",
                title=f"SPF is wide open ({all_mark}). Anyone can spoof.",
                target=domain, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="SPF policy allows ANY sender to claim this domain. Trivial spoofing.",
                data={"raw": spf["raw"]},
                tags=[ChainTag.DNS_SPF_PERMISSIVE],
                recommendation="Replace SPF `all` qualifier with `-all` (hardfail) immediately.",
            ))
    else:
        findings.append(issue(
            phase="dns_surface", check="spf_missing",
            title="No SPF record found",
            target=domain, severity=Severity.HIGH, confidence=Confidence.HIGH,
            description="Without SPF, anyone on the internet can spoof email from this domain.",
            tags=[ChainTag.DNS_SPF_MISSING],
            recommendation="Publish an SPF record. Minimal: `v=spf1 include:spf.protection.outlook.com -all`.",
        ))

    # DMARC parse (`_dmarc.{domain}`)
    dmarc_txt = await query(f"_dmarc.{domain}", "TXT")
    dmarc = parse_dmarc(dmarc_txt)
    if dmarc:
        policy = (dmarc.get("p") or "").lower()
        if policy == "none":
            findings.append(issue(
                phase="dns_surface", check="dmarc_p_none",
                title="DMARC policy is `p=none` (monitor only)",
                target=domain, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description="DMARC is published but receivers don't reject unauthorized mail. Domain remains spoofable in practice.",
                data={"raw": dmarc["raw"], "policy": policy},
                tags=[ChainTag.DNS_DMARC_NONE],
                recommendation="Move DMARC from `p=none` to `p=quarantine`, then `p=reject` after 30-90 days of monitoring reports.",
            ))
        elif policy == "quarantine":
            findings.append(validation(
                phase="dns_surface", check="dmarc_p_quarantine",
                title="DMARC at `p=quarantine`",
                target=domain,
                payload={"raw": dmarc["raw"], **dmarc},
                tags=[ChainTag.DNS_DMARC_QUARANTINE],
            ))
        elif policy == "reject":
            findings.append(validation(
                phase="dns_surface", check="dmarc_p_reject",
                title="DMARC at `p=reject` — enforced",
                target=domain,
                payload={"raw": dmarc["raw"], **dmarc},
                tags=[ChainTag.DNS_DMARC_REJECT],
            ))
    else:
        findings.append(issue(
            phase="dns_surface", check="dmarc_missing",
            title="No DMARC record at `_dmarc`",
            target=domain, severity=Severity.HIGH, confidence=Confidence.HIGH,
            description="Without DMARC, receivers have no policy guidance on SPF/DKIM failures. Domain is highly spoofable.",
            tags=[ChainTag.DNS_DMARC_MISSING],
            recommendation="Publish DMARC starting at `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com;` to begin monitoring.",
        ))

    # DKIM (Microsoft uses selector1 / selector2 by default)
    dkim_present = []
    for sel in ("selector1", "selector2"):
        rec = await query(f"{sel}._domainkey.{domain}", "CNAME")
        if not rec:
            rec = await query(f"{sel}._domainkey.{domain}", "TXT")
        if rec:
            dkim_present.append(sel)
            findings.append(data(
                phase="dns_surface", check=f"dkim_{sel}",
                title=f"DKIM selector `{sel}` present",
                target=domain, confidence=Confidence.HIGH,
                payload={"name": f"{sel}._domainkey.{domain}", "rtype": "CNAME/TXT", "value": ", ".join(rec)},
                tags=[ChainTag.DNS_DKIM_PRESENT],
            ))
    if not dkim_present:
        findings.append(issue(
            phase="dns_surface", check="dkim_missing",
            title="No M365 DKIM selectors found",
            target=domain, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            description="M365 default DKIM selectors (`selector1`, `selector2`) are not published. Mail goes out without DKIM signature.",
            tags=[ChainTag.DNS_DKIM_MISSING],
            recommendation="Enable DKIM signing in Microsoft 365 Defender → Email & collaboration → Policies → DKIM, then publish the CNAME records Microsoft provides.",
        ))

    # M365 ancillary CNAMEs
    cname_targets = {
        "autodiscover": ChainTag.DNS_AUTODISCOVER_O365,
        "enterpriseregistration": ChainTag.DNS_ENTERPRISE_REGISTRATION,
        "enterpriseenrollment": ChainTag.DNS_ENTERPRISE_ENROLLMENT,
        "lyncdiscover": ChainTag.DNS_LYNCDISCOVER,
        "msoid": ChainTag.DNS_MSOID_LEGACY,
        "sip": None,
    }
    for prefix, tag in cname_targets.items():
        rec = await query(f"{prefix}.{domain}", "CNAME")
        if not rec:
            rec = await query(f"{prefix}.{domain}", "A")
        if rec:
            findings.append(data(
                phase="dns_surface", check=f"cname_{prefix}",
                title=f"DNS hint: {prefix}.{domain} → {rec[0]}",
                target=f"{prefix}.{domain}", confidence=Confidence.HIGH,
                payload={"name": f"{prefix}.{domain}", "rtype": "CNAME/A", "value": rec[0]},
                tags=[tag] if tag else [],
            ))

    # SRV records of interest
    for srv in ("_sipfederationtls._tcp", "_sip._tls", "_sip._tcp"):
        rec = await query(f"{srv}.{domain}", "SRV")
        if rec:
            findings.append(data(
                phase="dns_surface", check=f"srv_{srv}",
                title=f"SRV record present: {srv}.{domain}",
                target=f"{srv}.{domain}", confidence=Confidence.HIGH,
                payload={"name": f"{srv}.{domain}", "rtype": "SRV", "value": rec[0]},
                tags=[ChainTag.DNS_SIPFEDERATION] if "_sipfederationtls" in srv else [],
            ))

    return findings
