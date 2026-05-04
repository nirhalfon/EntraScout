"""Pydantic data models for findings, leads, issues, and the run context."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class FindingKind(str, Enum):
    DATA = "DATA"           # raw discovered data (tenant id, domain list, etc)
    LEAD = "LEAD"           # actionable next step / pivot opportunity
    ISSUE = "ISSUE"         # security weakness / misconfig
    VALIDATION = "VALIDATION"  # confirmed-correct configuration


# Stable IDs for chain-graph tags. Keep ALL_CAPS, dash-separated.
class ChainTag(str, Enum):
    # Tenant
    TENANT_CONFIRMED = "TENANT-CONFIRMED"
    TENANT_REGION_KNOWN = "TENANT-REGION-KNOWN"
    TENANT_DOMAINS_ENUMERATED = "TENANT-DOMAINS-ENUMERATED"
    TENANT_BRANDING_LEAKED = "TENANT-BRANDING-LEAKED"

    # Federation / IdP
    FED_MANAGED = "FED-MANAGED"
    FED_FEDERATED = "FED-FEDERATED"
    FED_ADFS_DETECTED = "FED-ADFS-DETECTED"
    FED_ADFS_MEX_EXPOSED = "FED-ADFS-MEX-EXPOSED"
    FED_THIRDPARTY_IDP = "FED-THIRDPARTY-IDP"
    FED_AAD_CONNECT_PHS = "FED-AAD-CONNECT-PHS"
    FED_AAD_CONNECT_PTA = "FED-AAD-CONNECT-PTA"
    FED_SEAMLESS_SSO = "FED-SEAMLESS-SSO"

    # Users
    USER_ENUM_GETCREDTYPE = "USER-ENUM-GETCREDTYPE"
    USER_ENUM_ONEDRIVE = "USER-ENUM-ONEDRIVE"
    USER_ENUM_TEAMS = "USER-ENUM-TEAMS"
    USER_VALIDATED_NPLUS = "USER-VALIDATED-NPLUS"

    # Services exposed
    SVC_SHAREPOINT = "SVC-SHAREPOINT"
    SVC_ONEDRIVE = "SVC-ONEDRIVE"
    SVC_EXCHANGE = "SVC-EXCHANGE"
    SVC_OWA = "SVC-OWA"
    SVC_ECP = "SVC-ECP"
    SVC_EWS = "SVC-EWS"
    SVC_ACTIVESYNC = "SVC-ACTIVESYNC"
    SVC_TEAMS = "SVC-TEAMS"
    SVC_LYNCDISCOVER = "SVC-LYNCDISCOVER"
    SVC_YAMMER = "SVC-YAMMER"
    SVC_BOOKINGS = "SVC-BOOKINGS"
    SVC_FORMS = "SVC-FORMS"
    SVC_SWAY = "SVC-SWAY"
    SVC_STREAM = "SVC-STREAM"
    SVC_LOOP = "SVC-LOOP"
    SVC_WHITEBOARD = "SVC-WHITEBOARD"

    # Auth / MFA / legacy
    LEGACY_AUTH_SMTP = "LEGACY-AUTH-SMTP"
    LEGACY_AUTH_IMAP = "LEGACY-AUTH-IMAP"
    LEGACY_AUTH_POP = "LEGACY-AUTH-POP"
    LEGACY_AUTH_EWS_BASIC = "LEGACY-AUTH-EWS-BASIC"
    LEGACY_AUTH_BLOCKED = "LEGACY-AUTH-BLOCKED"
    MFA_GAP_DETECTED = "MFA-GAP-DETECTED"
    SMART_LOCKOUT_INFERRED = "SMART-LOCKOUT-INFERRED"
    DEVICE_CODE_FLOW = "DEVICE-CODE-FLOW"
    FOCI_CLIENT_REACHABLE = "FOCI-CLIENT-REACHABLE"

    # DNS / mail
    DNS_MX_O365 = "DNS-MX-O365"
    DNS_AUTODISCOVER_O365 = "DNS-AUTODISCOVER-O365"
    DNS_SPF_OK = "DNS-SPF-OK"
    DNS_SPF_PERMISSIVE = "DNS-SPF-PERMISSIVE"
    DNS_SPF_MISSING = "DNS-SPF-MISSING"
    DNS_DMARC_NONE = "DNS-DMARC-NONE"
    DNS_DMARC_QUARANTINE = "DNS-DMARC-QUARANTINE"
    DNS_DMARC_REJECT = "DNS-DMARC-REJECT"
    DNS_DMARC_MISSING = "DNS-DMARC-MISSING"
    DNS_DKIM_PRESENT = "DNS-DKIM-PRESENT"
    DNS_DKIM_MISSING = "DNS-DKIM-MISSING"
    DNS_ENTERPRISE_REGISTRATION = "DNS-ENTERPRISE-REGISTRATION"
    DNS_ENTERPRISE_ENROLLMENT = "DNS-ENTERPRISE-ENROLLMENT"
    DNS_LYNCDISCOVER = "DNS-LYNCDISCOVER"
    DNS_MSOID_LEGACY = "DNS-MSOID-LEGACY"
    DNS_SIPFEDERATION = "DNS-SIPFEDERATION"

    # Azure / tenant-bound resources
    AZ_APPSERVICE = "AZ-APPSERVICE"
    AZ_KUDU_EXPOSED = "AZ-KUDU-EXPOSED"
    AZ_STATIC_WEBAPP = "AZ-STATIC-WEBAPP"
    AZ_CONTAINER_APP = "AZ-CONTAINER-APP"
    AZ_CONTAINER_REGISTRY = "AZ-CONTAINER-REGISTRY"
    AZ_FRONT_DOOR = "AZ-FRONT-DOOR"
    AZ_CDN = "AZ-CDN"
    AZ_BLOB = "AZ-BLOB"
    AZ_BLOB_PUBLIC_LISTING = "AZ-BLOB-PUBLIC-LISTING"
    AZ_FILE = "AZ-FILE"
    AZ_QUEUE = "AZ-QUEUE"
    AZ_TABLE = "AZ-TABLE"
    AZ_SERVICEBUS = "AZ-SERVICEBUS"
    AZ_APIM = "AZ-APIM"
    AZ_COSMOS = "AZ-COSMOS"
    AZ_SEARCH = "AZ-SEARCH"
    AZ_DEVOPS_ORG = "AZ-DEVOPS-ORG"
    AZ_DEVOPS_PUBLIC_PROJECTS = "AZ-DEVOPS-PUBLIC-PROJECTS"
    AZ_DEVOPS_PUBLIC_WIKI = "AZ-DEVOPS-PUBLIC-WIKI"

    # Power Platform / Copilot / Dynamics
    PP_POWER_PAGES = "PP-POWER-PAGES"
    PP_POWER_PAGES_ODATA = "PP-POWER-PAGES-ODATA"
    PP_POWER_BI_PUBLISH = "PP-POWER-BI-PUBLISH"
    PP_DYNAMICS_ORG = "PP-DYNAMICS-ORG"
    PP_COPILOT_M365 = "PP-COPILOT-M365"
    PP_COPILOT_STUDIO = "PP-COPILOT-STUDIO"
    PP_COPILOT_PUBLIC_BOT = "PP-COPILOT-PUBLIC-BOT"

    # Identity / device / CA
    APP_PROXY_PUBLIC = "APP-PROXY-PUBLIC"
    MCAS_TENANT = "MCAS-TENANT"
    CTAP_INFERRED = "CTAP-INFERRED"

    # v0.1.6 — expanded recon coverage
    SVC_BOOKINGS_PUBLIC = "SVC-BOOKINGS-PUBLIC"
    SVC_FORMS_PUBLIC = "SVC-FORMS-PUBLIC"
    SVC_STREAM_PUBLIC = "SVC-STREAM-PUBLIC"
    SVC_LOOP_PUBLIC = "SVC-LOOP-PUBLIC"
    SVC_POWERBI_PUBLIC = "SVC-POWERBI-PUBLIC"
    SVC_YAMMER_EXTERNAL = "SVC-YAMMER-EXTERNAL"
    SVC_INTUNE_DETECTED = "SVC-INTUNE-DETECTED"
    AZ_KEYVAULT = "AZ-KEYVAULT"
    AZ_OPENAI = "AZ-OPENAI"
    AZ_COGNITIVE = "AZ-COGNITIVE"
    AZ_RECOVERY_VAULT = "AZ-RECOVERY-VAULT"
    AZ_APPSERVICE_SLOT = "AZ-APPSERVICE-SLOT"
    AZ_LOGIC_APP_TRIGGER = "AZ-LOGIC-APP-TRIGGER"
    AAD_APP_REGISTERED = "AAD-APP-REGISTERED"
    AAD_B2C_TENANT = "AAD-B2C-TENANT"
    GUEST_INFERRED = "GUEST-INFERRED"
    GITHUB_LEAK = "GITHUB-LEAK"
    PACKAGE_LEAK = "PACKAGE-LEAK"
    WAYBACK_HIT = "WAYBACK-HIT"
    DEFENDER_LEAK = "DEFENDER-LEAK"
    MIP_LABEL_LEAK = "MIP-LABEL-LEAK"
    CERT_SAN_LEAK = "CERT-SAN-LEAK"


# What each tag enables (chain edges). Used by the path-finder.
TAG_ENABLES: dict[ChainTag, list[str]] = {
    ChainTag.FED_ADFS_MEX_EXPOSED: ["forge-saml-token", "golden-saml-attack"],
    ChainTag.FED_THIRDPARTY_IDP: ["idp-targeted-phish", "idp-cve-lookup"],
    ChainTag.FED_SEAMLESS_SSO: ["aadconnect-pivot", "hash-of-hash"],
    ChainTag.USER_ENUM_GETCREDTYPE: ["password-spray", "phishing"],
    ChainTag.USER_ENUM_ONEDRIVE: ["password-spray", "phishing"],
    ChainTag.USER_ENUM_TEAMS: ["password-spray", "phishing", "teams-external-chat"],
    ChainTag.USER_VALIDATED_NPLUS: ["high-confidence-spray-list"],
    ChainTag.LEGACY_AUTH_SMTP: ["legacy-spray-no-mfa"],
    ChainTag.LEGACY_AUTH_IMAP: ["legacy-spray-no-mfa"],
    ChainTag.LEGACY_AUTH_POP: ["legacy-spray-no-mfa"],
    ChainTag.LEGACY_AUTH_EWS_BASIC: ["legacy-spray-no-mfa", "ews-data-exfil"],
    ChainTag.MFA_GAP_DETECTED: ["mfa-bypass-spray"],
    ChainTag.DEVICE_CODE_FLOW: ["device-code-phish"],
    ChainTag.FOCI_CLIENT_REACHABLE: ["foci-token-attacks"],
    ChainTag.DNS_DMARC_NONE: ["spoof-domain-phish"],
    ChainTag.DNS_DMARC_MISSING: ["spoof-domain-phish"],
    ChainTag.DNS_SPF_PERMISSIVE: ["spoof-domain-phish"],
    ChainTag.DNS_SPF_MISSING: ["spoof-domain-phish"],
    ChainTag.DNS_DKIM_MISSING: ["spoof-relay-phish"],
    ChainTag.AZ_KUDU_EXPOSED: ["code-exec", "env-secret-leak"],
    ChainTag.AZ_BLOB_PUBLIC_LISTING: ["data-exfil", "pivot"],
    ChainTag.AZ_DEVOPS_PUBLIC_WIKI: ["credential-leak", "infra-doc-leak"],
    ChainTag.AZ_DEVOPS_PUBLIC_PROJECTS: ["source-code-leak"],
    ChainTag.AZ_CONTAINER_REGISTRY: ["supply-chain-recon", "image-pull"],
    ChainTag.PP_POWER_PAGES_ODATA: ["dataverse-exfil-unauth"],
    ChainTag.PP_POWER_BI_PUBLISH: ["data-exfil-unauth"],
    ChainTag.PP_COPILOT_PUBLIC_BOT: ["prompt-injection-data-exfil"],
    ChainTag.APP_PROXY_PUBLIC: ["legacy-app-direct-attack"],
    ChainTag.SVC_OWA: ["owa-credential-phish", "ews-discovery"],
    ChainTag.SVC_ECP: ["ecp-admin-attacks"],
    ChainTag.SVC_BOOKINGS: ["user-email-harvest"],
    ChainTag.SVC_FORMS: ["public-content-harvest"],
    ChainTag.TENANT_BRANDING_LEAKED: ["phishing-page-clone"],
}


# MITRE ATT&CK technique IDs per tag (for the chain map)
TAG_MITRE: dict[ChainTag, list[str]] = {
    ChainTag.FED_ADFS_MEX_EXPOSED: ["T1606.002", "T1199"],
    ChainTag.FED_SEAMLESS_SSO: ["T1199", "T1078.004"],
    ChainTag.USER_ENUM_GETCREDTYPE: ["T1087.004", "T1589.002"],
    ChainTag.USER_ENUM_ONEDRIVE: ["T1087.004", "T1589.002"],
    ChainTag.USER_ENUM_TEAMS: ["T1087.004"],
    ChainTag.LEGACY_AUTH_SMTP: ["T1110.003", "T1078.004"],
    ChainTag.LEGACY_AUTH_IMAP: ["T1110.003"],
    ChainTag.LEGACY_AUTH_POP: ["T1110.003"],
    ChainTag.LEGACY_AUTH_EWS_BASIC: ["T1110.003", "T1114.002"],
    ChainTag.MFA_GAP_DETECTED: ["T1556.006"],
    ChainTag.DEVICE_CODE_FLOW: ["T1566", "T1078.004"],
    ChainTag.DNS_DMARC_MISSING: ["T1566.001"],
    ChainTag.DNS_SPF_PERMISSIVE: ["T1566.001"],
    ChainTag.AZ_KUDU_EXPOSED: ["T1190", "T1552.001"],
    ChainTag.AZ_BLOB_PUBLIC_LISTING: ["T1530"],
    ChainTag.AZ_DEVOPS_PUBLIC_WIKI: ["T1213.003", "T1552"],
    ChainTag.PP_POWER_PAGES_ODATA: ["T1213"],
    ChainTag.PP_POWER_BI_PUBLISH: ["T1213"],
    ChainTag.PP_COPILOT_PUBLIC_BOT: ["T1059"],
    ChainTag.APP_PROXY_PUBLIC: ["T1133"],
    ChainTag.TENANT_BRANDING_LEAKED: ["T1583.001"],
}


class Evidence(BaseModel):
    """Reference to raw evidence saved on disk (e.g. raw HTTP response)."""
    path: str
    description: str = ""


class Finding(BaseModel):
    """Unified finding type: data, lead, issue, validation."""
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    phase: str
    check: str
    title: str
    kind: FindingKind
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    description: str = ""
    target: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    tags: list[ChainTag] = Field(default_factory=list)
    enables: list[str] = Field(default_factory=list)  # populated from TAG_ENABLES at write time
    mitre: list[str] = Field(default_factory=list)
    recommendation: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def hydrate_chain(self) -> None:
        """Populate enables / mitre from tags."""
        en: set[str] = set()
        mit: set[str] = set()
        for t in self.tags:
            for e in TAG_ENABLES.get(t, []):
                en.add(e)
            for m in TAG_MITRE.get(t, []):
                mit.add(m)
        self.enables = sorted(en)
        self.mitre = sorted(mit)


class TenantSnapshot(BaseModel):
    """Top-level tenant identity dump."""
    target_input: str
    primary_domain: str | None = None
    tenant_id: str | None = None
    tenant_default_name: str | None = None  # the .onmicrosoft.com prefix
    tenant_region: str | None = None
    tenant_cloud: str | None = None  # Public / GCC / GCC-High / China / Gov
    issuer: str | None = None
    federation_type: str | None = None  # Managed / Federated / Unknown
    federated_idp: str | None = None
    auth_url: str | None = None
    seamless_sso: bool | None = None
    aad_connect_type: str | None = None
    custom_domains: list[dict[str, Any]] = Field(default_factory=list)
    branding: dict[str, Any] = Field(default_factory=dict)


class RunContext(BaseModel):
    """Run-wide configuration and state."""
    target: str
    output_root: str
    run_id: str
    started_at: datetime
    mode_internal: bool = False
    user_hint: str | None = None
    token: str | None = None  # never written to disk
    bing_api_key: str | None = None  # never written to disk
    quick: bool = False
    stealth: bool = False
    selected_phases: list[str] | None = None
    timeout: float = 8.0
    workers: int = 32
    qps: float | None = None  # if stealth, defaults to 3
    proxy: str | None = None

    class Config:
        # Don't dump secrets to JSON
        json_schema_extra = {"hidden": ["token", "bing_api_key"]}
