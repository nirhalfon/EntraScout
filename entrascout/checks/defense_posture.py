"""Phase 8 — Defense posture (heuristic) — synthesize signals from earlier phases.

Most of this runs by inspecting prior findings, not new probes.
"""
from __future__ import annotations

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, issue, lead, validation


def _has_tag(findings: list[Finding], tag: ChainTag) -> bool:
    return any(tag in f.tags for f in findings)


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager,
              prior_findings: list[Finding] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    prior = prior_findings or []

    legacy_blocked = _has_tag(prior, ChainTag.LEGACY_AUTH_BLOCKED)
    legacy_open = any(t in [ChainTag.LEGACY_AUTH_SMTP, ChainTag.LEGACY_AUTH_IMAP, ChainTag.LEGACY_AUTH_POP, ChainTag.MFA_GAP_DETECTED]
                      for f in prior for t in f.tags)
    spf_ok = _has_tag(prior, ChainTag.DNS_SPF_OK)
    spf_bad = any(t in [ChainTag.DNS_SPF_PERMISSIVE, ChainTag.DNS_SPF_MISSING] for f in prior for t in f.tags)
    dmarc_reject = _has_tag(prior, ChainTag.DNS_DMARC_REJECT)
    dmarc_quarantine = _has_tag(prior, ChainTag.DNS_DMARC_QUARANTINE)
    dmarc_bad = any(t in [ChainTag.DNS_DMARC_NONE, ChainTag.DNS_DMARC_MISSING] for f in prior for t in f.tags)
    dkim_present = _has_tag(prior, ChainTag.DNS_DKIM_PRESENT)
    dkim_missing = _has_tag(prior, ChainTag.DNS_DKIM_MISSING)

    # Mail-spoofing posture — single roll-up
    posture: list[str] = []
    severity = Severity.INFO
    if dmarc_reject and spf_ok and dkim_present:
        posture.append("DMARC reject + strict SPF + DKIM present")
    else:
        if dmarc_bad:
            posture.append("DMARC weak/missing")
            severity = Severity.HIGH
        elif dmarc_quarantine:
            posture.append("DMARC quarantine (good, push to reject)")
            severity = max(severity, Severity.LOW, key=lambda s: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s.value))
        if spf_bad:
            posture.append("SPF weak/missing")
            severity = Severity.HIGH
        if dkim_missing:
            posture.append("DKIM missing")

    if posture:
        # validation() doesn't accept severity= (it's hardcoded INFO).
        # Pick the right helper for the severity bucket and call it with the right kwargs.
        common = dict(
            phase="defense_posture", check="mail_spoofing_posture",
            title=f"Mail-spoofing posture: {'; '.join(posture)}",
            target=ctx.target,
            description="Roll-up of SPF/DMARC/DKIM. Domain spoofing is a top phishing surface.",
        )
        rec = (
            "Targets: SPF `-all` with `include:spf.protection.outlook.com`, "
            "DMARC `p=reject` with `rua=` reporting, DKIM with both M365 selectors enabled."
        )
        if severity in (Severity.HIGH, Severity.CRITICAL):
            findings.append(issue(**common, severity=severity, confidence=Confidence.HIGH, recommendation=rec))
        elif severity == Severity.INFO:
            findings.append(validation(**common))
        else:
            findings.append(lead(**common, severity=severity, confidence=Confidence.HIGH, recommendation=rec))

    # Legacy auth posture
    if legacy_blocked and not legacy_open:
        findings.append(validation(
            phase="defense_posture", check="legacy_auth_blocked",
            title="Conditional Access blocks legacy auth (good)",
            target=ctx.target, payload={},
        ))
    elif legacy_open:
        findings.append(issue(
            phase="defense_posture", check="legacy_auth_surface_exposed",
            title="Legacy authentication surface is reachable",
            target=ctx.target, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            description="Legacy auth endpoints accept connections. Even if specific accounts are blocked by CA, the TCP/SMTP/IMAP/POP surface remains an attacker convenience.",
            recommendation="Block legacy authentication tenant-wide via Conditional Access, then disable each protocol per-mailbox where unused.",
        ))

    # Federation posture roll-up
    if _has_tag(prior, ChainTag.FED_ADFS_MEX_EXPOSED):
        findings.append(lead(
            phase="defense_posture", check="adfs_attack_surface",
            title="ADFS attack surface exposed externally",
            target=ctx.target, severity=Severity.HIGH, confidence=Confidence.HIGH,
            description="ADFS is exposed externally with MEX/FederationMetadata reachable. Combined with on-prem foothold, Golden SAML is achievable.",
            recommendation="Reduce ADFS external exposure: WAP/Web Application Proxy in front, restrict /mex and /FederationMetadata. Plan migration to Pass-Through Auth or cloud-only.",
        ))

    return findings
