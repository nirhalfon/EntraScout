"""Pydantic schemas for the web API."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PhaseInfo(BaseModel):
    id: str
    name: str
    description: str


class ScanCreateRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    phases: list[str] | None = None
    quick: bool = False
    stealth: bool = False
    internal: bool = False
    timeout: float = 8.0
    workers: int = 32
    token: str | None = None
    bing_key: str | None = None
    user_hint: str | None = None


class ScanResponse(BaseModel):
    run_id: str
    target: str
    status: str
    started_at: str
    finished_at: str | None = None
    counts: dict[str, Any] | None = None
    snapshot: dict[str, Any] | None = None
    error: str | None = None


class ScanEvent(BaseModel):
    type: str
    phase: str | None = None
    findings_count: int | None = None
    finding: dict[str, Any] | None = None
    error: str | None = None
    message: str | None = None
    counts: dict[str, Any] | None = None
