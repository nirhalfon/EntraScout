"""DNS helpers — sync via dnspython, used inside thread executor for async callers."""
from __future__ import annotations

import asyncio
from typing import Any

import dns.resolver
import dns.rdatatype


def _resolver(timeout: float = 4.0, nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    if nameservers:
        r.nameservers = nameservers
    r.lifetime = timeout
    r.timeout = timeout
    return r


def query_sync(name: str, rtype: str, *, timeout: float = 4.0) -> list[str]:
    try:
        ans = _resolver(timeout=timeout).resolve(name, rtype, raise_on_no_answer=False)
        return [r.to_text() for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:  # noqa: BLE001
        return []


async def query(name: str, rtype: str, *, timeout: float = 4.0) -> list[str]:
    return await asyncio.to_thread(query_sync, name, rtype, timeout=timeout)


async def collect(name: str, types: list[str] | None = None, *, timeout: float = 4.0) -> dict[str, list[str]]:
    types = types or ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV"]
    out: dict[str, list[str]] = {}
    results = await asyncio.gather(*(query(name, t, timeout=timeout) for t in types))
    for t, r in zip(types, results):
        if r:
            out[t] = r
    return out


def clean_txt(values: list[str]) -> list[str]:
    cleaned: list[str] = []
    for v in values:
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        cleaned.append(v.replace('" "', ""))
    return cleaned


def parse_spf(txt_records: list[str]) -> dict[str, Any] | None:
    for raw in clean_txt(txt_records):
        s = raw.strip()
        if s.lower().startswith("v=spf1"):
            return {
                "raw": s,
                "includes": [tok[len("include:"):] for tok in s.split() if tok.lower().startswith("include:")],
                "all": next((tok for tok in s.split() if tok.lower().endswith("all")), None),
            }
    return None


def parse_dmarc(txt_records: list[str]) -> dict[str, Any] | None:
    for raw in clean_txt(txt_records):
        s = raw.strip()
        if s.lower().startswith("v=dmarc1"):
            parts = {kv.split("=")[0].strip().lower(): kv.split("=", 1)[1].strip() for kv in s.split(";") if "=" in kv}
            return {"raw": s, **parts}
    return None
