"""Smoke tests — make sure the modules import and core wiring works without network."""
from __future__ import annotations

import json
from pathlib import Path

from entrascout.chain import build_chain, render_attack_paths_md
from entrascout.models import (
    ChainTag,
    Confidence,
    Finding,
    FindingKind,
    Severity,
    TenantSnapshot,
)


def test_models_serialization() -> None:
    f = Finding(
        phase="dns_surface",
        check="dmarc_missing",
        title="No DMARC",
        kind=FindingKind.ISSUE,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        target="example.com",
        tags=[ChainTag.DNS_DMARC_MISSING, ChainTag.USER_ENUM_GETCREDTYPE],
    )
    f.hydrate_chain()
    assert "spoof-domain-phish" in f.enables
    assert "T1566.001" in f.mitre
    js = json.dumps(f.model_dump(mode="json"))
    assert "DNS-DMARC-MISSING" in js


def test_chain_attack_paths() -> None:
    findings = [
        Finding(phase="dns_surface", check="dmarc_missing", title="x",
                kind=FindingKind.ISSUE, severity=Severity.HIGH,
                target="example.com", tags=[ChainTag.DNS_DMARC_MISSING]),
        Finding(phase="user_enum", check="user_enum_getcredtype", title="x",
                kind=FindingKind.DATA, severity=Severity.INFO,
                target="ceo@example.com", tags=[ChainTag.USER_ENUM_GETCREDTYPE]),
    ]
    for f in findings:
        f.hydrate_chain()
    chain = build_chain(findings, "example.com")
    assert chain["summary"]["total_paths"] >= 1
    md = render_attack_paths_md(chain)
    assert "Attack Paths" in md


def test_tenant_snapshot_roundtrip() -> None:
    s = TenantSnapshot(target_input="example.com", tenant_id="abc-123",
                       custom_domains=[{"domain": "example.com", "type": "Managed"}])
    js = json.dumps(s.model_dump(mode="json"))
    s2 = TenantSnapshot.model_validate_json(js)
    assert s2.tenant_id == "abc-123"
