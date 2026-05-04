"""Phase 21 — OneDrive / SharePoint anonymous-link pattern probe (gap #9).

Anonymous SharePoint / OneDrive sharing links follow predictable patterns:

    https://{tenant}-my.sharepoint.com/:x:/g/personal/{user_email_dotted}/{B64_token}

The B64 token is high-entropy (~22 chars random), unbrute-forceable. What we
CAN do:
- Confirm `{tenant}-my.sharepoint.com` exists (probably already done by m365_services)
- Construct dorks that route an attacker (or our human auditor) to leaked links
  on Bing / Google
- Probe the personal site root for users we already enumerated

This is reconnaissance / hunting prep; no link-token brute force.
"""
from __future__ import annotations

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, lead, is_existence_signal


async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]:
    findings: list[Finding] = []
    tenant_short = (snap.tenant_default_name or "").replace(".onmicrosoft.com", "")
    if not tenant_short:
        return findings

    sp_root = f"https://{tenant_short}.sharepoint.com"
    od_root = f"https://{tenant_short}-my.sharepoint.com"

    # Build the dork pack
    findings.append(data(
        phase="onedrive_links", check="onedrive_anonymous_link_dorks",
        title="OneDrive / SharePoint anonymous-link search dorks",
        target=od_root, confidence=Confidence.HIGH,
        payload={
            "od_root": od_root,
            "sp_root": sp_root,
            "dorks": [
                f'site:{tenant_short}-my.sharepoint.com',
                f'site:{tenant_short}.sharepoint.com inurl:":x:/g/personal/"',
                f'site:{tenant_short}.sharepoint.com "guestaccess.aspx"',
                f'site:{tenant_short}.sharepoint.com "personal" filetype:pdf OR filetype:xlsx OR filetype:docx',
                f'"{tenant_short}.sharepoint.com" "anonymous link"',
            ],
            "url_pattern": f"{od_root}/:x:/g/personal/{{user_dotted}}/{{B64_TOKEN_22}}",
            "note": "B64 token is high-entropy; only Bing-found leaks are practical.",
        },
        tags=[ChainTag.SVC_ONEDRIVE],
    ))

    # Probe SP root existence as confirmation
    r = await http.head(sp_root)
    if not r:
        r = await http.get(sp_root)
    if r and is_existence_signal(r.status_code):
        findings.append(data(
            phase="onedrive_links", check="sharepoint_root_reachable",
            title=f"SharePoint Online root reachable: {sp_root}",
            target=sp_root, confidence=Confidence.HIGH,
            payload={"url": sp_root, "status": r.status_code},
            tags=[ChainTag.SVC_SHAREPOINT],
        ))

    return findings
