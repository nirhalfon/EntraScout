"""Shared helpers used by check modules."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from ..models import ChainTag, Confidence, Evidence, Finding, FindingKind, Severity

GUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def lead(
    *,
    phase: str,
    check: str,
    title: str,
    description: str = "",
    target: str = "",
    severity: Severity = Severity.INFO,
    confidence: Confidence = Confidence.MEDIUM,
    data: dict[str, Any] | None = None,
    tags: list[ChainTag] | None = None,
    recommendation: str = "",
    evidence: list[Evidence] | None = None,
) -> Finding:
    return Finding(
        phase=phase, check=check, title=title, description=description, target=target,
        kind=FindingKind.LEAD, severity=severity, confidence=confidence,
        data=data or {}, tags=tags or [], recommendation=recommendation, evidence=evidence or [],
    )


def issue(
    *,
    phase: str,
    check: str,
    title: str,
    description: str = "",
    target: str = "",
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.MEDIUM,
    data: dict[str, Any] | None = None,
    tags: list[ChainTag] | None = None,
    recommendation: str = "",
    evidence: list[Evidence] | None = None,
) -> Finding:
    return Finding(
        phase=phase, check=check, title=title, description=description, target=target,
        kind=FindingKind.ISSUE, severity=severity, confidence=confidence,
        data=data or {}, tags=tags or [], recommendation=recommendation, evidence=evidence or [],
    )


def data(
    *,
    phase: str,
    check: str,
    title: str,
    description: str = "",
    target: str = "",
    confidence: Confidence = Confidence.HIGH,
    payload: dict[str, Any] | None = None,
    tags: list[ChainTag] | None = None,
    evidence: list[Evidence] | None = None,
) -> Finding:
    return Finding(
        phase=phase, check=check, title=title, description=description, target=target,
        kind=FindingKind.DATA, severity=Severity.INFO, confidence=confidence,
        data=payload or {}, tags=tags or [], evidence=evidence or [],
    )


def validation(
    *,
    phase: str,
    check: str,
    title: str,
    description: str = "",
    target: str = "",
    payload: dict[str, Any] | None = None,
    tags: list[ChainTag] | None = None,
) -> Finding:
    return Finding(
        phase=phase, check=check, title=title, description=description, target=target,
        kind=FindingKind.VALIDATION, severity=Severity.INFO, confidence=Confidence.HIGH,
        data=payload or {}, tags=tags or [],
    )


def host_for(url: str) -> str:
    return urlparse(url).hostname or url


def is_2xx_or_redirect(code: int) -> bool:
    return 200 <= code < 400


def is_existence_signal(code: int) -> bool:
    """Many MS endpoints return 401/403/404 on existence, but the existence is real."""
    return code in (200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 503)


def normalize_target(target: str) -> str:
    """Strip schemes/paths, lower, take the registrable hostname."""
    target = target.strip().lower()
    if "://" in target:
        target = urlparse(target).hostname or target
    target = target.rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    return target
