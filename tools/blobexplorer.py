#!/usr/bin/env python3
"""blobexplorer — interactive Azure Blob Storage anonymous browser.

Usage:
  blobexplorer.py <account>                          # probe well-known containers
  blobexplorer.py <account> -c <container>           # list blobs in container
  blobexplorer.py <account> -c <container> --grep PATTERN
  blobexplorer.py <account> -c <container> --download <DIR> [--limit N]
  blobexplorer.py <account> -c <container> --head <BLOB_NAME>
  blobexplorer.py <account> --attribute <brand_domain>

Examples:
  blobexplorer.py dhsfiles
  blobexplorer.py dhsfiles -c files
  blobexplorer.py dhsfiles -c files --grep '\\.pdf$'
  blobexplorer.py dhsfiles -c files --download ./loot --limit 5
  blobexplorer.py dhsfiles --attribute dhs.gov

Read-only: only does anonymous GETs. No auth, no writes.
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree as ET

try:
    import httpx
except ImportError:
    print("ERROR: needs httpx. Activate the EntraScout venv:")
    print("  cd /Users/osher/EntraScout && source .venv/bin/activate")
    sys.exit(2)


WELL_KNOWN_CONTAINERS = [
    # Common
    "files", "file", "uploads", "upload", "media", "images", "assets",
    "documents", "document", "docs", "data", "public", "static",
    "backup", "backups", "logs", "log", "archive", "temp", "tmp",
    "config", "configs", "scripts", "tools", "exports", "downloads",
    # Azure-default-ish
    "container1", "test", "dev", "prod", "stage", "staging",
    "$logs", "$web", "$root",
    # App-specific
    "share", "shared", "private", "internal", "external",
    "reports", "report", "videos", "video", "audio",
    # MS Power Platform
    "powerplatform", "dataverse", "power-bi", "logic-apps",
    # CDN-ish
    "cdn", "wwwroot",
]

SENSITIVE_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".json", ".sql",
    ".zip", ".tar", ".gz", ".bak", ".dump", ".env", ".pem", ".key",
    ".pfx", ".p12", ".cer", ".crt", ".kdbx", ".pst", ".ost",
    ".xml", ".yaml", ".yml", ".conf", ".cfg", ".ini",
}
SENSITIVE_TOKENS = {
    "password", "passwd", "secret", "credential", "creds", "token",
    "apikey", "api-key", "private", "internal", "confidential",
    "salary", "payroll", "ssn", "personal", "pii",
    "backup", "dump", "export", "report",
}

NS = {"a": "http://schemas.microsoft.com/windowsazure"}  # not actually used (no namespace)


def url_account(account: str) -> str:
    if account.startswith("http"):
        return account.rstrip("/")
    return f"https://{account}.blob.core.windows.net"


def list_blobs(client: httpx.Client, account: str, container: str, max_n: int = 5000) -> list[dict]:
    """Anonymous list_blobs. Returns list of {name, size, last_modified, content_type, url}."""
    base = url_account(account)
    blobs: list[dict] = []
    marker = None
    while True:
        params = {
            "restype": "container",
            "comp": "list",
            "maxresults": "500",
        }
        if marker:
            params["marker"] = marker
        last_err = None
        r = None
        for attempt in range(3):
            try:
                r = client.get(f"{base}/{container}", params=params, timeout=60)
                break
            except httpx.HTTPError as e:
                last_err = e
                time.sleep(0.5 * (attempt + 1))
        if r is None:
            print(f"  request failed after retries: {last_err}")
            break
        if r.status_code == 404:
            return []
        if r.status_code in (401, 403):
            print(f"  container '{container}' not anonymously listable (HTTP {r.status_code})")
            return []
        if r.status_code != 200:
            print(f"  HTTP {r.status_code}: {r.text[:150]}")
            return []
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError:
            print("  XML parse failed")
            return blobs
        for b in root.findall(".//Blob"):
            name = (b.findtext("Name") or "").strip()
            props = b.find("Properties")
            size = props.findtext("Content-Length") if props is not None else ""
            mod = props.findtext("Last-Modified") if props is not None else ""
            ctype = props.findtext("Content-Type") if props is not None else ""
            blobs.append({
                "name": name,
                "size": int(size) if size and size.isdigit() else 0,
                "last_modified": mod or "",
                "content_type": ctype or "",
                "url": f"{base}/{container}/{quote(name)}",
            })
            if len(blobs) >= max_n:
                return blobs
        marker = (root.findtext("NextMarker") or "").strip()
        if not marker:
            break
    return blobs


def is_sensitive(name: str) -> tuple[bool, str]:
    low = name.lower()
    for ext in SENSITIVE_EXT:
        if low.endswith(ext):
            return True, f"ext={ext}"
    for tok in SENSITIVE_TOKENS:
        if tok in low:
            return True, f"token={tok}"
    return False, ""


def probe_containers(client: httpx.Client, account: str, names: list[str]) -> list[tuple[str, int, int]]:
    """Probe a list of container names. Returns [(name, status, blob_count_if_listable)]."""
    base = url_account(account)
    out: list[tuple[str, int, int]] = []
    for c in names:
        try:
            r = client.get(f"{base}/{c}", params={"restype": "container", "comp": "list", "maxresults": "1"}, timeout=8)
        except httpx.HTTPError:
            continue
        if r.status_code == 200:
            try:
                root = ET.fromstring(r.content)
                # quick count via list with maxresults=5000 in second pass — just signal here
                out.append((c, 200, 1 if root.find(".//Blob") is not None else 0))
            except ET.ParseError:
                out.append((c, 200, -1))
        elif r.status_code in (401, 403):
            out.append((c, r.status_code, 0))
        # 404 ignored
    return out


def humansize(n: int) -> str:
    for u in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"


def cmd_probe(args, client):
    """Probe well-known container names on the account."""
    print(f"[*] probing well-known containers on {args.account}.blob.core.windows.net")
    hits = probe_containers(client, args.account, WELL_KNOWN_CONTAINERS)
    if not hits:
        print("  no anonymously listable containers found in well-known set")
        print("  try: blobexplorer.py <account> -c <custom_name>")
        return
    for name, status, has_blobs in hits:
        if status == 200:
            print(f"  [OPEN]  {name}  (has blobs: {'yes' if has_blobs else 'empty'})")
        else:
            print(f"  [{status}]   {name}")


def cmd_list(args, client):
    print(f"[*] listing {args.account}/{args.container}")
    blobs = list_blobs(client, args.account, args.container)
    if not blobs:
        print("  empty or not listable")
        return
    pat = re.compile(args.grep) if args.grep else None
    sensitive_only = args.sensitive
    shown = 0
    total_size = 0
    sensitive_count = 0
    for b in blobs:
        sens, why = is_sensitive(b["name"])
        if sens:
            sensitive_count += 1
        if pat and not pat.search(b["name"]):
            continue
        if sensitive_only and not sens:
            continue
        flag = "!" if sens else " "
        print(f"  [{flag}] {b['name']:<70}  {humansize(b['size']):>9}  {b['last_modified'][:25]}  {why}")
        shown += 1
        total_size += b["size"]
    print(f"\n[*] total blobs: {len(blobs)}  shown: {shown}  sensitive: {sensitive_count}  size_shown: {humansize(total_size)}")


def cmd_head(args, client):
    base = url_account(args.account)
    url = f"{base}/{args.container}/{quote(args.head)}"
    print(f"[*] HEAD {url}")
    try:
        r = client.head(url, timeout=15)
    except httpx.HTTPError as e:
        print(f"  failed: {e}")
        return
    print(f"  status: {r.status_code}")
    for k, v in r.headers.items():
        print(f"  {k}: {v}")
    # Show first 512 bytes
    if r.status_code == 200:
        print(f"\n[*] first 512 bytes:")
        rg = client.get(url, headers={"Range": "bytes=0-511"}, timeout=15)
        # Try to decode as text
        try:
            print(rg.content.decode("utf-8", errors="replace"))
        except Exception:
            print(rg.content[:512])


def cmd_download(args, client):
    blobs = list_blobs(client, args.account, args.container)
    if args.grep:
        pat = re.compile(args.grep)
        blobs = [b for b in blobs if pat.search(b["name"])]
    if args.sensitive:
        blobs = [b for b in blobs if is_sensitive(b["name"])[0]]
    if args.limit:
        blobs = blobs[: args.limit]
    if not blobs:
        print("  nothing to download")
        return
    out = Path(args.download)
    out.mkdir(parents=True, exist_ok=True)
    print(f"[*] downloading {len(blobs)} blobs to {out}")
    for b in blobs:
        # Flatten path with safe name
        safe = b["name"].replace("/", "_").replace("\\", "_")
        target = out / safe
        try:
            r = client.get(b["url"], timeout=30)
            if r.status_code == 200:
                target.write_bytes(r.content)
                print(f"  ok  {b['name']}  -> {target}  ({humansize(len(r.content))})")
            else:
                print(f"  HTTP {r.status_code}  {b['name']}")
        except httpx.HTTPError as e:
            print(f"  fail  {b['name']}  {e}")
        time.sleep(0.05)  # be polite


def cmd_attribute(args, client):
    """Heuristic attribution check: does this account belong to <brand_domain>?"""
    brand = args.attribute.lower()
    print(f"[*] attribution heuristics: {args.account} <-> {brand}")
    score = 0.0
    reasons = []

    # Name-based
    brand_root = brand.split(".")[0]
    if brand_root in args.account.lower():
        score += 0.3
        reasons.append(f"account name contains '{brand_root}' (+0.3)")

    # Sample first 5 blobs from each well-known container, look for brand in content
    hits = probe_containers(client, args.account, WELL_KNOWN_CONTAINERS)
    open_containers = [c for c, s, _ in hits if s == 200]
    print(f"  open containers: {open_containers or '(none)'}")
    sample_hits = 0
    for c in open_containers[:3]:
        blobs = list_blobs(client, args.account, c, max_n=20)
        for b in blobs[:5]:
            if brand_root in b["name"].lower():
                score += 0.05
                reasons.append(f"blob name '{b['name']}' contains '{brand_root}'")
                sample_hits += 1
            try:
                r = client.get(b["url"], headers={"Range": "bytes=0-2047"}, timeout=10)
                txt = r.content.decode("utf-8", errors="replace").lower()
                if brand in txt or brand_root in txt:
                    score += 0.1
                    reasons.append(f"content of '{b['name']}' references '{brand}'")
                    sample_hits += 1
                    if sample_hits > 5:
                        break
            except Exception:
                pass
        if sample_hits > 5:
            break

    print(f"\n  attribution score: {score:.2f}  (>0.4 = likely; >0.7 = confident)")
    for r in reasons:
        print(f"    - {r}")


def main() -> int:
    p = argparse.ArgumentParser(description="Anonymous Azure Blob explorer")
    p.add_argument("account", help="storage account name (e.g. dhsfiles) or full URL")
    p.add_argument("-c", "--container", help="container name")
    p.add_argument("--grep", help="regex filter on blob name")
    p.add_argument("--sensitive", action="store_true", help="show only sensitive-looking blobs")
    p.add_argument("--download", help="download blobs to this directory")
    p.add_argument("--limit", type=int, help="cap on number of blobs to download")
    p.add_argument("--head", help="HEAD a specific blob and dump headers + first bytes")
    p.add_argument("--attribute", help="run attribution heuristics against a brand domain")
    args = p.parse_args()

    headers = {"User-Agent": "blobexplorer/1.0 (+anon-readonly)"}
    with httpx.Client(headers=headers, follow_redirects=True) as client:
        if args.attribute:
            cmd_attribute(args, client)
        elif args.head and args.container:
            cmd_head(args, client)
        elif args.download and args.container:
            cmd_download(args, client)
        elif args.container:
            cmd_list(args, client)
        else:
            cmd_probe(args, client)
    return 0


if __name__ == "__main__":
    sys.exit(main())
