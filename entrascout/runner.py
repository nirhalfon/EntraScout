"""Phase orchestrator — runs phases in dependency order, hands findings to OutputManager."""
from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pathlib import Path

from .checks import PHASES
from .checks._helpers import normalize_target
from .chain import build_chain, render_attack_paths_md
from .http_client import StealthClient
from .logging import HistoryWriter, get_logger, reattach_to_dir
from .models import RunContext, TenantSnapshot
from .output import OutputManager
from .report import render_html, render_exec_summary


# The order matters — earlier phases populate the snapshot used by later phases.
DEFAULT_ORDER = ["1", "2", "5", "3", "4", "13", "14", "11", "12", "6", "7", "8", "9", "10"]
INTERNAL_ORDER = DEFAULT_ORDER + ["internal"]


async def _run_phase(name: str, mod: Any, ctx: RunContext, http: StealthClient,
                     snap: TenantSnapshot, om: OutputManager,
                     prior: list[Any],
                     phase_callback: Callable[[dict[str, Any]], Coroutine[Any, Any, None]] | None = None) -> list[Any]:
    log = get_logger("entrascout.runner")
    log.info("--- Phase: %s ---", name)
    if phase_callback:
        try:
            await phase_callback({"type": "phase_start", "phase": name})
        except Exception:  # noqa: BLE001
            pass
    try:
        if name == "defense_posture":
            findings = await mod.run(ctx, http, snap, om, prior_findings=prior)
        else:
            findings = await mod.run(ctx, http, snap, om)
        log.info("[%s] %d finding(s)", name, len(findings))
        if phase_callback:
            try:
                await phase_callback({"type": "phase_end", "phase": name, "findings_count": len(findings)})
            except Exception:  # noqa: BLE001
                pass
        return findings
    except Exception as e:  # noqa: BLE001
        log.exception("Phase %s failed: %s", name, e)
        if phase_callback:
            try:
                await phase_callback({"type": "phase_error", "phase": name, "error": str(e)})
            except Exception:  # noqa: BLE001
                pass
        return []


async def run_engagement(
    *,
    target: str,
    output_root: str = "./output",
    mode_internal: bool = False,
    user_hint: str | None = None,
    token: str | None = None,
    bing_api_key: str | None = None,
    quick: bool = False,
    stealth: bool = False,
    selected_phases: list[str] | None = None,
    timeout: float = 8.0,
    workers: int = 32,
    proxy: str | None = None,
    history_writer: HistoryWriter | None = None,
    output_manager: OutputManager | None = None,
    phase_callback: Callable[[dict[str, Any]], Coroutine[Any, Any, None]] | None = None,
) -> dict[str, Any]:
    target = normalize_target(target)
    om = output_manager or OutputManager(output_root, target)

    # Move logging + history into the per-run dir now that it exists.
    # IMPORTANT: when called concurrently (batch mode), reattaching mutates
    # the GLOBAL logger and races with sibling runs. Caller must opt-in to
    # the reattach by NOT passing a history_writer; if a writer was provided
    # by the caller (batch mode), keep it and skip reattach.
    if history_writer is None:
        history_writer = reattach_to_dir(Path(om.run_dir))

    ctx = RunContext(
        target=target,
        output_root=output_root,
        run_id=om.run_id,
        started_at=datetime.now(timezone.utc),
        mode_internal=mode_internal,
        user_hint=user_hint,
        token=token,
        bing_api_key=bing_api_key,
        quick=quick,
        stealth=stealth,
        selected_phases=selected_phases,
        timeout=timeout,
        workers=workers,
        qps=3.0 if stealth else None,
        proxy=proxy,
    )

    log = get_logger("entrascout.runner")
    log.info("Run %s starting against target=%s mode=%s",
             om.run_id, target, "INTERNAL" if mode_internal else "EXTERNAL")

    snap = TenantSnapshot(target_input=target)

    order = selected_phases or (INTERNAL_ORDER if mode_internal else DEFAULT_ORDER)

    async with StealthClient(
        timeout=timeout,
        qps=ctx.qps,
        proxy=proxy,
        history_writer=history_writer,
        logger=get_logger("entrascout.http"),
    ) as http:
        all_findings: list[Any] = []
        for key in order:
            entry = PHASES.get(key)
            if not entry:
                continue
            name, mod = entry
            results = await _run_phase(name, mod, ctx, http, snap, om, all_findings, phase_callback)
            for f in results:
                om.add(f)
            all_findings.extend(results)

    # Build chain map
    chain = build_chain(om.findings, target)
    om.write_json("chain.json", chain)
    om.write_text("attack_paths.md", render_attack_paths_md(chain))

    # Finalize core artifacts
    artifacts = om.finalize(ctx, snap)

    # Counts for HTML
    by_kind = chain["summary"]["by_severity"]
    counts = {
        "total": sum(1 for _ in om.findings),
        "critical": by_kind.get("CRITICAL", 0),
        "high": by_kind.get("HIGH", 0),
        "medium": by_kind.get("MEDIUM", 0),
        "low": by_kind.get("LOW", 0),
        "info": by_kind.get("INFO", 0),
        "leads": sum(1 for f in om.findings if f.kind.value == "LEAD"),
        "issues": sum(1 for f in om.findings if f.kind.value == "ISSUE"),
        "validations": sum(1 for f in om.findings if f.kind.value == "VALIDATION"),
        "data": sum(1 for f in om.findings if f.kind.value == "DATA"),
    }

    run_meta = {
        "run_id": om.run_id,
        "target": target,
        "started_at": ctx.started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "mode_internal": mode_internal,
    }

    html_path = render_html(
        findings=om.findings,
        snapshot=snap,
        chain=chain,
        counts=counts,
        run_meta=run_meta,
        out_path=Path(om.run_dir) / "report.html",
    )
    artifacts["report.html"] = str(html_path)

    # Exec-summary (1-page, print/PDF-ready)
    exec_path = render_exec_summary(
        findings=om.findings,
        snapshot=snap,
        chain=chain,
        counts=counts,
        run_meta=run_meta,
        out_path=Path(om.run_dir) / "executive_summary.html",
    )
    artifacts["executive_summary.html"] = str(exec_path)

    log.info("Run complete. Output dir: %s", om.run_dir)
    return {
        "run_dir": str(om.run_dir),
        "artifacts": artifacts,
        "counts": counts,
        "snapshot": snap.model_dump(mode="json"),
        "chain_summary": chain["summary"],
    }
