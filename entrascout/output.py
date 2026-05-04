"""Per-run output manager — creates the run folder and writes all artifacts."""
from __future__ import annotations

import csv
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding, FindingKind, RunContext, Severity, TenantSnapshot


def _serialize_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if hasattr(obj, "value"):  # Enum
        return obj.value
    return str(obj)


def _safe_short_id() -> str:
    return secrets.token_hex(4)


class OutputManager:
    """Stages a per-run folder, then writes all artifacts."""

    def __init__(self, base_root: str | os.PathLike[str], target: str) -> None:
        self.target = target
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.run_id = f"{ts}_{_safe_short_id()}"
        self.run_dir = Path(base_root) / f"run_{self.run_id}"
        self.raw_dir = self.run_dir / "raw"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self._findings: list[Finding] = []

    # ------- ingestion -------
    def add(self, finding: Finding) -> Finding:
        finding.hydrate_chain()
        self._findings.append(finding)
        return finding

    def extend(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add(f)

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    # ------- raw evidence -------
    def save_raw(self, name: str, content: str | bytes) -> Path:
        p = self.raw_dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8", errors="replace")
        return p

    def relpath(self, p: Path | str) -> str:
        return str(Path(p).relative_to(self.run_dir))

    # ------- JSON / CSV / MD writers -------
    def write_json(self, name: str, payload: Any) -> Path:
        path = self.run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=_serialize_default), encoding="utf-8")
        return path

    def write_jsonl(self, name: str, items: list[Any]) -> Path:
        path = self.run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for item in items:
                f.write(json.dumps(item, default=_serialize_default))
                f.write("\n")
        return path

    def write_csv(self, name: str, rows: list[dict[str, Any]], columns: list[str] | None = None) -> Path:
        path = self.run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not rows:
            path.write_text("", encoding="utf-8")
            return path
        cols = columns or sorted({k for r in rows for k in r.keys()})
        with path.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({c: ("" if r.get(c) is None else r.get(c)) for c in cols})
        return path

    def write_text(self, name: str, content: str) -> Path:
        path = self.run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    # ------- finalization -------
    def finalize(self, ctx: RunContext, snapshot: TenantSnapshot) -> dict[str, str]:
        """Write all artifacts. Returns a map of artifact-name → path."""
        for f in self._findings:
            f.hydrate_chain()

        sev_order = {s: i for i, s in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])}
        self._findings.sort(key=lambda x: (sev_order.get(x.severity.value, 99), x.phase, x.check))

        leads = [f for f in self._findings if f.kind == FindingKind.LEAD]
        issues = [f for f in self._findings if f.kind == FindingKind.ISSUE]
        validations = [f for f in self._findings if f.kind == FindingKind.VALIDATION]
        data = [f for f in self._findings if f.kind == FindingKind.DATA]

        artifacts: dict[str, str] = {}

        # Pure data
        artifacts["tenant.json"] = str(self.write_json("tenant.json", snapshot.model_dump(mode="json")))
        artifacts["findings.json"] = str(self.write_json("findings.json", [f.model_dump(mode="json") for f in self._findings]))
        artifacts["findings.jsonl"] = str(self.write_jsonl("findings.jsonl", [f.model_dump(mode="json") for f in self._findings]))
        artifacts["leads.json"] = str(self.write_json("leads.json", [f.model_dump(mode="json") for f in leads]))
        artifacts["issues.json"] = str(self.write_json("issues.json", [f.model_dump(mode="json") for f in issues]))
        artifacts["validations.json"] = str(self.write_json("validations.json", [f.model_dump(mode="json") for f in validations]))
        artifacts["data.json"] = str(self.write_json("data.json", [f.model_dump(mode="json") for f in data]))

        # CSV: services
        svc_rows = [
            {"service": f.data.get("service", f.check), "url": f.data.get("url", ""),
             "status": f.data.get("status", ""), "title": f.title, "severity": f.severity.value}
            for f in self._findings if f.data.get("url")
        ]
        artifacts["services.csv"] = str(self.write_csv("services.csv", svc_rows,
            columns=["service", "url", "status", "title", "severity"]))

        # CSV: users
        user_rows = [
            {"user": f.data.get("user", ""), "valid": f.data.get("valid", ""),
             "method": f.data.get("method", f.check), "confidence": f.confidence.value}
            for f in self._findings if f.check.startswith("user_enum") and f.data.get("user")
        ]
        artifacts["users.csv"] = str(self.write_csv("users.csv", user_rows,
            columns=["user", "valid", "method", "confidence"]))

        # CSV: dns
        dns_rows = [
            {"name": f.data.get("name", ""), "rtype": f.data.get("rtype", ""), "value": f.data.get("value", "")}
            for f in self._findings if f.phase == "dns_surface" and f.data.get("rtype")
        ]
        artifacts["dns.csv"] = str(self.write_csv("dns.csv", dns_rows,
            columns=["name", "rtype", "value"]))

        # CSV: azure resources
        az_rows = [
            {"resource_type": f.data.get("resource_type", ""), "host": f.data.get("host", ""),
             "status": f.data.get("status", ""), "evidence": f.title, "severity": f.severity.value}
            for f in self._findings if f.phase in ("azure_resources", "identity_edges")
        ]
        artifacts["azure_resources.csv"] = str(self.write_csv("azure_resources.csv", az_rows,
            columns=["resource_type", "host", "status", "evidence", "severity"]))

        # Recommendations markdown — issues AND leads
        rec_lines = [
            "# Recommendations\n\n",
            f"_Generated by EntraScout against `{ctx.target}`._\n\n",
            "## 🔴 Issues (security misconfigs)\n\n",
        ]
        any_issue = False
        for f in issues:
            if f.recommendation:
                any_issue = True
                rec_lines.append(f"### {f.title}\n")
                rec_lines.append(f"- **Severity:** {f.severity.value}\n")
                rec_lines.append(f"- **Phase:** {f.phase} / {f.check}\n")
                rec_lines.append(f"- **Target:** `{f.target}`\n\n")
                rec_lines.append(f"{f.recommendation}\n\n")
                rec_lines.append("---\n\n")
        if not any_issue:
            rec_lines.append("_No issues with recommendations._\n\n")

        rec_lines.append("\n## 🎯 Leads (next-step opportunities)\n\n")
        any_lead = False
        for f in leads:
            if f.recommendation:
                any_lead = True
                rec_lines.append(f"### {f.title}\n")
                rec_lines.append(f"- **Severity:** {f.severity.value}\n")
                rec_lines.append(f"- **Phase:** {f.phase} / {f.check}\n")
                rec_lines.append(f"- **Target:** `{f.target}`\n\n")
                rec_lines.append(f"{f.recommendation}\n\n")
                rec_lines.append("---\n\n")
        if not any_lead:
            rec_lines.append("_No lead recommendations._\n\n")
        artifacts["recommendations.md"] = str(self.write_text("recommendations.md", "".join(rec_lines)))

        # Run metadata (no secrets)
        meta = ctx.model_dump(mode="json", exclude={"token", "bing_api_key"})
        meta["finished_at"] = datetime.now(timezone.utc).isoformat()
        meta["finding_counts"] = {
            "total": len(self._findings),
            "critical": sum(1 for f in self._findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in self._findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in self._findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in self._findings if f.severity == Severity.LOW),
            "info": sum(1 for f in self._findings if f.severity == Severity.INFO),
            "leads": len(leads),
            "issues": len(issues),
            "validations": len(validations),
            "data": len(data),
        }
        artifacts["run.json"] = str(self.write_json("run.json", meta))

        return artifacts
