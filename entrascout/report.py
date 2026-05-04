"""HTML report renderer."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import Finding, FindingKind, Severity, TenantSnapshot


_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _serialize(o: Any) -> Any:
    if hasattr(o, "model_dump"):
        return o.model_dump(mode="json")
    if hasattr(o, "value"):
        return o.value
    return str(o)


def render_html(
    *,
    findings: list[Finding],
    snapshot: TenantSnapshot,
    chain: dict[str, Any],
    counts: dict[str, int],
    run_meta: dict[str, Any],
    out_path: Path,
) -> Path:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=select_autoescape())
    tpl = env.get_template("report.html.j2")
    issues = [f for f in findings if f.kind == FindingKind.ISSUE]
    leads = [f for f in findings if f.kind == FindingKind.LEAD]
    validations = [f for f in findings if f.kind == FindingKind.VALIDATION]
    data = [f for f in findings if f.kind == FindingKind.DATA]
    rendered = tpl.render(
        snapshot=snapshot,
        snapshot_json=json.dumps(snapshot.model_dump(mode="json"), indent=2, default=_serialize),
        chain=chain,
        issues=issues,
        leads=leads,
        validations=validations,
        data=data,
        counts=counts,
        run_meta=run_meta,
    )
    out_path.write_text(rendered, encoding="utf-8")
    return out_path


def render_exec_summary(
    *,
    findings: list[Finding],
    snapshot: TenantSnapshot,
    chain: dict[str, Any],
    counts: dict[str, int],
    run_meta: dict[str, Any],
    out_path: Path,
) -> Path:
    """Render a 1-page exec-friendly summary, print/PDF-ready.

    Use with browser print -> Save as PDF for an audit-deliverable.
    No extra dependencies (weasyprint etc.) required.
    """
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=select_autoescape())
    tpl = env.get_template("exec_summary.html.j2")
    issues = [f for f in findings if f.kind == FindingKind.ISSUE]
    rendered = tpl.render(
        snapshot=snapshot,
        chain=chain,
        issues=issues,
        counts=counts,
        run_meta=run_meta,
    )
    out_path.write_text(rendered, encoding="utf-8")
    return out_path
