"""Async SQLite persistence for scan results."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import aiosqlite

DB_PATH = os.environ.get("ENTRASCOUT_DB", "./data/entrascout.db")


async def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                run_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                options TEXT,
                started_at TEXT,
                finished_at TEXT,
                counts TEXT,
                snapshot TEXT,
                chain TEXT,
                error TEXT
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                phase TEXT,
                `check` TEXT,
                title TEXT,
                kind TEXT,
                severity TEXT,
                confidence TEXT,
                description TEXT,
                target TEXT,
                data TEXT,
                tags TEXT,
                enables TEXT,
                mitre TEXT,
                recommendation TEXT,
                evidence TEXT,
                discovered_at TEXT,
                FOREIGN KEY (run_id) REFERENCES scans (run_id)
            )
            """
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id)"
        )
        await db.commit()


async def create_scan(run_id: str, target: str, status: str, options: dict[str, Any]) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO scans (run_id, target, status, options, started_at) VALUES (?, ?, ?, ?, ?)",
            (run_id, target, status, json.dumps(options), datetime.now(timezone.utc).isoformat()),
        )
        await db.commit()


async def update_scan(run_id: str, **kwargs: Any) -> None:
    fields: list[str] = []
    values: list[Any] = []
    for k, v in kwargs.items():
        fields.append(f"{k} = ?")
        if isinstance(v, (dict, list)):
            values.append(json.dumps(v))
        else:
            values.append(v)
    values.append(run_id)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            f"UPDATE scans SET {', '.join(fields)} WHERE run_id = ?",
            values,
        )
        await db.commit()


async def add_finding(run_id: str, finding: dict[str, Any]) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO findings (
                id, run_id, phase, `check`, title, kind, severity, confidence,
                description, target, data, tags, enables, mitre, recommendation,
                evidence, discovered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.get("id"),
                run_id,
                finding.get("phase"),
                finding.get("check"),
                finding.get("title"),
                finding.get("kind"),
                finding.get("severity"),
                finding.get("confidence"),
                finding.get("description"),
                finding.get("target"),
                json.dumps(finding.get("data", {})),
                json.dumps(finding.get("tags", [])),
                json.dumps(finding.get("enables", [])),
                json.dumps(finding.get("mitre", [])),
                finding.get("recommendation"),
                json.dumps(finding.get("evidence", [])),
                finding.get("discovered_at"),
            ),
        )
        await db.commit()


async def get_scan(run_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM scans WHERE run_id = ?", (run_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return dict(row)


async def list_scans(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def get_findings(run_id: str) -> list[dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        async with db.execute(
            "SELECT * FROM findings WHERE run_id = ?", (run_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            findings = [dict(r) for r in rows]
            for f in findings:
                f["data"] = json.loads(f["data"]) if f.get("data") else {}
                f["tags"] = json.loads(f["tags"]) if f.get("tags") else []
                f["enables"] = json.loads(f["enables"]) if f.get("enables") else []
                f["mitre"] = json.loads(f["mitre"]) if f.get("mitre") else []
                f["evidence"] = json.loads(f["evidence"]) if f.get("evidence") else []
            findings.sort(
                key=lambda x: (
                    sev_order.get(x.get("severity", ""), 99),
                    x.get("phase", ""),
                    x.get("check", ""),
                )
            )
            return findings


async def delete_scan(run_id: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
        await db.execute("DELETE FROM scans WHERE run_id = ?", (run_id,))
        await db.commit()
