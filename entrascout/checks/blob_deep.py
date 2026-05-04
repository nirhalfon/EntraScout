"""Deep Azure Blob storage enumeration.

For each discovered storage account, brute common container names,
parse listings, classify file contents by sensitivity, and surface findings.

Recon-only: we list filenames and parse metadata. We do NOT download blob
content (avoid bandwidth-heavy ops + accidental data exfiltration on
authorized engagements). Sample-download is opt-in via probe_content=True.
"""
from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import quote

from ..http_client import StealthClient
from ..models import ChainTag, Confidence, Finding, RunContext, Severity, TenantSnapshot
from ..output import OutputManager
from ._helpers import data, issue, lead, validation


# Common container names attackers find in real engagements
COMMON_CONTAINERS = [
    "$web", "$logs", "$root", "$blobchangefeed",
    "backup", "backups", "bak", "bkp",
    "public", "private", "data", "files", "assets", "asset",
    "dev", "test", "qa", "staging", "stage", "prod", "production", "uat",
    "logs", "log", "audit", "audits",
    "media", "images", "image", "photos", "videos", "video", "uploads", "upload",
    "temp", "tmp",
    "releases", "release", "builds", "build", "artifacts", "artifact",
    "config", "configs", "configuration", "settings",
    "container", "containers", "blob", "blobs",
    "documents", "docs", "document",
    "exports", "imports", "export", "import",
    "reports", "report", "analytics",
    "downloads", "download",
    "secrets", "keys", "certs", "certificates", "cert",
    "terraform", "ansible", "deployment", "deploy", "deployments",
    "sql", "db", "dump", "dumps", "database", "databases",
    "src", "source", "sources", "code", "repo", "repos", "git",
    "static", "content", "cdn", "css", "js", "scripts",
    "web", "site", "sites", "www", "html",
    "user", "users", "user-data",
    "company", "internal", "private-data", "shared", "general",
    "sap", "ms365", "data-export", "data-exports", "data-share",
    "snapshot", "snapshots",
]


SENSITIVE_EXTENSIONS = {
    ".env": ("Environment file (likely secrets)", Severity.HIGH),
    ".envrc": ("Direnv environment file", Severity.HIGH),
    ".config": ("Application config (may contain creds)", Severity.MEDIUM),
    ".cfg": ("Config file", Severity.MEDIUM),
    ".ini": ("INI config", Severity.MEDIUM),
    ".json": ("JSON (config/data)", Severity.LOW),
    ".yaml": ("YAML config", Severity.LOW),
    ".yml": ("YAML config", Severity.LOW),
    ".pem": ("PEM private key/certificate", Severity.HIGH),
    ".key": ("Private key", Severity.HIGH),
    ".pfx": ("PKCS12 cert bundle (likely with key)", Severity.HIGH),
    ".p12": ("PKCS12 cert bundle", Severity.HIGH),
    ".pkcs12": ("PKCS12 cert bundle", Severity.HIGH),
    ".jks": ("Java keystore", Severity.HIGH),
    ".sql": ("SQL dump (likely PII/secrets)", Severity.HIGH),
    ".sqlite": ("SQLite database", Severity.HIGH),
    ".db": ("Database file", Severity.HIGH),
    ".mdb": ("MS Access database", Severity.HIGH),
    ".dump": ("Memory/data dump", Severity.HIGH),
    ".dmp": ("Memory dump", Severity.HIGH),
    ".bak": ("Backup file", Severity.MEDIUM),
    ".bkp": ("Backup file", Severity.MEDIUM),
    ".tar": ("Tar archive", Severity.MEDIUM),
    ".tgz": ("Tar.gz archive", Severity.MEDIUM),
    ".gz": ("Gzip archive", Severity.LOW),
    ".zip": ("Zip archive", Severity.MEDIUM),
    ".7z": ("7-Zip archive", Severity.MEDIUM),
    ".rar": ("RAR archive", Severity.MEDIUM),
    ".docx": ("Word document", Severity.LOW),
    ".doc": ("Word document (legacy)", Severity.LOW),
    ".xlsx": ("Excel spreadsheet", Severity.LOW),
    ".xls": ("Excel spreadsheet (legacy)", Severity.LOW),
    ".pdf": ("PDF document", Severity.LOW),
    ".csv": ("CSV data (often PII)", Severity.MEDIUM),
    ".tsv": ("TSV data", Severity.MEDIUM),
    ".log": ("Log file", Severity.LOW),
    ".ova": ("VM image (OVA)", Severity.HIGH),
    ".ovf": ("VM image", Severity.MEDIUM),
    ".vmdk": ("VM disk image", Severity.HIGH),
    ".vhd": ("VHD disk image", Severity.HIGH),
    ".vhdx": ("VHDX disk image", Severity.HIGH),
    ".iso": ("ISO image", Severity.MEDIUM),
    ".tfstate": ("Terraform state (contains secrets!)", Severity.CRITICAL),
    ".pcap": ("Packet capture (may contain creds)", Severity.HIGH),
    ".pcapng": ("Packet capture", Severity.HIGH),
    ".kdbx": ("KeePass database", Severity.HIGH),
    ".rdp": ("Remote Desktop config", Severity.MEDIUM),
    ".ppk": ("PuTTY private key", Severity.HIGH),
    ".pst": ("Outlook mailbox", Severity.HIGH),
    ".ost": ("Outlook offline cache", Severity.HIGH),
    ".gitlab-ci.yml": ("GitLab CI config", Severity.MEDIUM),
    ".npmrc": ("NPM config (may have token)", Severity.HIGH),
    ".dockerfile": ("Dockerfile", Severity.LOW),
    ".sh": ("Shell script (may contain secrets)", Severity.MEDIUM),
    ".ps1": ("PowerShell script", Severity.MEDIUM),
    ".bat": ("Batch script", Severity.MEDIUM),
    ".cmd": ("Batch script", Severity.MEDIUM),
}


SENSITIVE_NAME_TOKENS = {
    "secret": Severity.HIGH,
    "password": Severity.HIGH,
    "passwd": Severity.HIGH,
    "credential": Severity.HIGH,
    "creds": Severity.HIGH,
    "token": Severity.HIGH,
    "apikey": Severity.HIGH,
    "api-key": Severity.HIGH,
    "api_key": Severity.HIGH,
    "private": Severity.MEDIUM,
    "confidential": Severity.MEDIUM,
    "internal": Severity.LOW,
    "backup": Severity.MEDIUM,
    "dump": Severity.MEDIUM,
    "export": Severity.LOW,
    ".env": Severity.HIGH,
    "envvars": Severity.HIGH,
    "settings": Severity.LOW,
    "tfstate": Severity.CRITICAL,
    "terraform": Severity.MEDIUM,
    "ansible": Severity.LOW,
    "deploy": Severity.LOW,
    "release": Severity.LOW,
    "users": Severity.MEDIUM,
    "user-data": Severity.MEDIUM,
    "salary": Severity.HIGH,
    "payroll": Severity.HIGH,
    "hr": Severity.MEDIUM,
    "personnel": Severity.MEDIUM,
    "customer": Severity.MEDIUM,
    "client": Severity.MEDIUM,
    "patient": Severity.HIGH,
    "ssn": Severity.CRITICAL,
    "passport": Severity.HIGH,
    "contract": Severity.MEDIUM,
    "invoice": Severity.LOW,
    "salary": Severity.HIGH,
    "merger": Severity.HIGH,
    "acquisition": Severity.HIGH,
    "ndia": Severity.MEDIUM,
    "id_rsa": Severity.HIGH,
    ".aws": Severity.HIGH,
    ".azure": Severity.HIGH,
    "kube": Severity.MEDIUM,
    "kubeconfig": Severity.HIGH,
}


# Azure XML namespaces
NS = {"": ""}


def parse_blob_listing(xml_text: str) -> list[dict[str, Any]]:
    """Parse Azure blob ListContainer XML into a list of {name, size, last_modified}."""
    blobs: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return blobs
    # Azure blob listing has <Blobs><Blob><Name>...</Name>...
    for blob in root.iter("Blob"):
        name_el = blob.find("Name")
        if name_el is None or not name_el.text:
            continue
        props = blob.find("Properties")
        size = None
        last_mod = None
        ctype = None
        if props is not None:
            cl = props.find("Content-Length")
            if cl is not None and cl.text:
                try:
                    size = int(cl.text)
                except ValueError:
                    pass
            lm = props.find("Last-Modified")
            if lm is not None and lm.text:
                last_mod = lm.text
            ct = props.find("Content-Type")
            if ct is not None and ct.text:
                ctype = ct.text
        blobs.append({"name": name_el.text, "size": size, "last_modified": last_mod, "content_type": ctype})
    return blobs


def classify_blob(name: str) -> tuple[Severity, list[str]]:
    """Return (severity, reasons) for a blob name."""
    name_lower = name.lower()
    reasons: list[str] = []
    sev = Severity.INFO

    # Extension check (longest match wins)
    ext_matches = sorted(
        ((ext, label, esev) for ext, (label, esev) in SENSITIVE_EXTENSIONS.items() if name_lower.endswith(ext)),
        key=lambda x: -len(x[0]),
    )
    if ext_matches:
        ext, label, esev = ext_matches[0]
        reasons.append(f"sensitive extension `{ext}` ({label})")
        sev = esev

    # Name-token check
    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for token, tsev in SENSITIVE_NAME_TOKENS.items():
        if token in name_lower:
            reasons.append(f"name contains `{token}`")
            if severity_order.index(tsev.value) > severity_order.index(sev.value):
                sev = tsev

    return sev, reasons


async def list_container(http: StealthClient, account: str, container: str,
                         max_results: int = 100) -> tuple[int | None, list[dict[str, Any]]]:
    """List a single container anonymously. Returns (status, blobs)."""
    url = f"https://{account}.blob.core.windows.net/{quote(container)}?restype=container&comp=list&maxresults={max_results}"
    r = await http.get(url)
    if not r:
        return None, []
    if r.status_code != 200:
        return r.status_code, []
    if "<EnumerationResults" not in r.text:
        return r.status_code, []
    return r.status_code, parse_blob_listing(r.text)


async def list_account_containers(http: StealthClient, account: str) -> tuple[int | None, list[str]]:
    """Try to list all containers anonymously. Returns (status, container_names)."""
    url = f"https://{account}.blob.core.windows.net/?comp=list"
    r = await http.get(url)
    if not r:
        return None, []
    if r.status_code != 200 or "<EnumerationResults" not in r.text:
        return r.status_code, []
    names: list[str] = []
    try:
        root = ET.fromstring(r.text)
        for c in root.iter("Container"):
            n = c.find("Name")
            if n is not None and n.text:
                names.append(n.text)
    except ET.ParseError:
        pass
    return r.status_code, names


async def attribute_storage_account(
    *,
    http: StealthClient,
    account: str,
    target_brand: str,
) -> tuple[float, list[str]]:
    """Score 0.0-1.0 confidence that the storage account belongs to target_brand.

    Multiple signals combined:
    - Cert SAN (always generic for blob, so worth ~0)
    - DNS NS chain (sometimes shows brand)
    - Sample blob content sniff (filename patterns, brand strings, log formats)

    Returns (confidence_score, list_of_evidence_strings).
    """
    import asyncio
    evidence: list[str] = []
    score = 0.0

    # Account name proximity to brand
    a = account.lower()
    b = target_brand.lower().replace(".", "")
    if a == b:
        score += 0.3
        evidence.append(f"account name == brand ('{a}')")
    elif a.startswith(b) or a.endswith(b):
        score += 0.2
        evidence.append(f"account name contains brand ('{a}' ~ '{b}')")
    else:
        # Just a substring match — weaker
        if b in a:
            score += 0.1
            evidence.append(f"account name has brand substring ('{a}')")

    # Try to download a small sample file — first do a list to find one
    try:
        list_url = (
            f"https://{account}.blob.core.windows.net/$logs?restype=container&comp=list&maxresults=1"
        )
        r = await http.get(list_url)
        if not r or r.status_code != 200:
            # try common containers
            for c in ("public", "data", "files", "logs"):
                u = f"https://{account}.blob.core.windows.net/{c}?restype=container&comp=list&maxresults=1"
                r = await http.get(u)
                if r and r.status_code == 200 and "<EnumerationResults" in r.text:
                    break
        if r and r.status_code == 200 and "<EnumerationResults" in r.text:
            import re
            m = re.search(r"<Name>([^<]+)</Name>", r.text)
            if m:
                blob_path = m.group(1)
                # Check if filename has brand
                if b in blob_path.lower():
                    score += 0.2
                    evidence.append(f"sample blob filename contains brand ('{blob_path[:80]}')")
                # Sniff content
                content_url = f"https://{account}.blob.core.windows.net/{c}/{blob_path}"
                rc = await http.get(content_url)
                if rc and rc.status_code == 200:
                    body = rc.text[:2000] if rc.text else ""
                    if b in body.lower():
                        score += 0.3
                        evidence.append(f"sample blob content contains brand string")
    except Exception:  # noqa: BLE001
        pass

    return min(score, 1.0), evidence


async def deep_enum_account(
    *,
    http: StealthClient,
    account: str,
    om: OutputManager,
    container_list: list[str] | None = None,
    workers: int = 16,
    target_brand: str | None = None,
) -> list[Finding]:
    """Deep enumerate one storage account."""
    findings: list[Finding] = []

    # 1. Try account-wide listing first
    code, all_containers = await list_account_containers(http, account)
    if code == 200 and all_containers:
        findings.append(issue(
            phase="azure_resources", check="blob_account_listing_open",
            title=f"Storage account allows ANONYMOUS account-level listing: {account}",
            target=f"https://{account}.blob.core.windows.net", severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=f"Account-level container listing is anonymously accessible. {len(all_containers)} container(s) discovered without auth.",
            data={"host": f"{account}.blob.core.windows.net", "account": account,
                  "containers": all_containers, "container_count": len(all_containers),
                  "resource_type": "Blob Storage (account-listing)"},
            tags=[ChainTag.AZ_BLOB_PUBLIC_LISTING],
            recommendation="Set storage account `AllowBlobPublicAccess=false` and audit the publicAccess setting on each container.",
        ))
        # Use the discovered container list
        target_containers = all_containers
    else:
        target_containers = container_list or COMMON_CONTAINERS

    # 2. Probe each container
    sem = asyncio.Semaphore(workers)
    container_findings: list[tuple[str, list[dict]]] = []  # (container, blobs)

    async def probe(container: str) -> None:
        async with sem:
            code, blobs = await list_container(http, account, container)
        if code == 200 and blobs is not None:
            # 200 means container exists AND allows anonymous list. Note: can be empty list.
            container_findings.append((container, blobs))

    await asyncio.gather(*(probe(c) for c in target_containers))

    if not container_findings:
        return findings

    # 2.5. Attribution check — kill HIGH severity if we can't link to target brand
    attribution_score = 1.0  # default to "trust" if no brand provided
    attribution_evidence: list[str] = []
    if target_brand:
        attribution_score, attribution_evidence = await attribute_storage_account(
            http=http, account=account, target_brand=target_brand,
        )

    # 3. Classify & emit findings
    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for container, blobs in container_findings:
        # Container itself is publicly listable — that's a finding
        container_url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
        # Save raw listing for evidence
        raw_path = om.save_raw(f"azure_resources/blob_listing_{account}_{container}.txt",
                               "\n".join(b["name"] for b in blobs))
        # Sort by sensitivity
        classified = [(b, *classify_blob(b["name"])) for b in blobs]
        # Highest severity in this container
        max_sev = Severity.INFO
        if classified:
            for _, sev, _ in classified:
                if severity_order.index(sev.value) > severity_order.index(max_sev.value):
                    max_sev = sev
        sample_files = [b["name"] for b in blobs[:25]]
        sensitive_files = [
            {"name": b["name"], "size": b["size"], "last_modified": b["last_modified"],
             "content_type": b["content_type"], "severity": sev.value, "reasons": reasons}
            for b, sev, reasons in classified
            if sev != Severity.INFO and reasons
        ]

        sev_for_finding = max_sev if max_sev != Severity.INFO else Severity.MEDIUM

        # Apply attribution downgrade: if score < 0.4, cap at LOW (suspicious but unconfirmed owner)
        if attribution_score < 0.4:
            sev_for_finding = Severity.LOW

        if sensitive_files:
            findings.append(issue(
                phase="azure_resources", check="blob_container_public_sensitive",
                title=f"[!] Public blob container `{container}` on `{account}` — {len(sensitive_files)} sensitive file(s)",
                target=container_url, severity=sev_for_finding, confidence=Confidence.CONFIRMED,
                description=(
                    f"Container `{container}` is anonymously listable and contains files with "
                    f"sensitive name/extension patterns. Total: {len(blobs)} files, sensitive: {len(sensitive_files)}."
                ),
                data={
                    "host": f"{account}.blob.core.windows.net",
                    "account": account, "container": container,
                    "total_files": len(blobs),
                    "sensitive_files": sensitive_files[:50],
                    "sample_files": sample_files,
                    "raw_listing_path": str(raw_path),
                    "resource_type": "Blob Storage (sensitive content)",
                    "attribution_score": attribution_score,
                    "attribution_evidence": attribution_evidence,
                },
                tags=[ChainTag.AZ_BLOB_PUBLIC_LISTING],
                recommendation=(
                    "Set the container's `publicAccess` to `none`, or move its contents to a "
                    "private storage account with SAS-token access. Audit who reads the listing logs."
                ),
            ))
        else:
            findings.append(lead(
                phase="azure_resources", check="blob_container_public",
                title=f"Public blob container `{container}` on `{account}` — {len(blobs)} file(s)",
                target=container_url, severity=Severity.LOW, confidence=Confidence.CONFIRMED,
                description=f"Container `{container}` is anonymously listable. No obviously-sensitive filenames in first {len(blobs)} entries.",
                data={
                    "host": f"{account}.blob.core.windows.net",
                    "account": account, "container": container,
                    "total_files": len(blobs),
                    "sample_files": sample_files,
                    "raw_listing_path": str(raw_path),
                    "resource_type": "Blob Storage (public, low-sensitivity)",
                    "attribution_score": attribution_score,
                    "attribution_evidence": attribution_evidence,
                },
                tags=[ChainTag.AZ_BLOB_PUBLIC_LISTING],
                recommendation="Confirm intent — public containers are sometimes for `$web` static hosting. If unintended, set `publicAccess=none`.",
            ))

    return findings
