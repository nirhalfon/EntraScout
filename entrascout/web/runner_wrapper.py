"""Background runner that wraps the CLI engine for the web API."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..logging import HistoryWriter
from ..output import StreamingOutputManager
from ..runner import run_engagement
from .store import update_scan, add_finding
from .streamer import ScanStreamer


class NullHistoryWriter:
    """No-op history writer for concurrent web scans."""

    def emit(self, record: dict[str, Any]) -> None:
        pass

    def close(self) -> None:
        pass


WEB_OUTPUT_ROOT = os.environ.get("ENTRASCOUT_OUTPUT", "./web_output")


async def run_scan_background(
    run_id: str,
    params: dict[str, Any],
    streamer: ScanStreamer,
) -> None:
    target = params["target"]
    output_root = os.path.join(WEB_OUTPUT_ROOT, run_id)
    os.makedirs(output_root, exist_ok=True)

    async def event_callback(event: dict[str, Any]) -> None:
        await streamer.put(run_id, event)
        if event.get("type") == "finding":
            await add_finding(run_id, event["finding"])

    om = StreamingOutputManager(output_root, target, event_callback=event_callback)

    async def phase_callback(event: dict[str, Any]) -> None:
        await streamer.put(run_id, event)

    try:
        await update_scan(run_id, status="running")
        result = await run_engagement(
            target=target,
            output_root=output_root,
            mode_internal=params.get("internal", False),
            user_hint=params.get("user_hint"),
            token=params.get("token"),
            bing_api_key=params.get("bing_key"),
            quick=params.get("quick", False),
            stealth=params.get("stealth", False),
            selected_phases=params.get("phases"),
            timeout=params.get("timeout", 8.0),
            workers=params.get("workers", 32),
            output_manager=om,
            phase_callback=phase_callback,
            history_writer=NullHistoryWriter(),
        )

        run_dir = Path(result["run_dir"])
        root = Path(output_root)

        # Promote key artifacts to the run root for easy API serving
        for artifact_name in [
            "report.html",
            "executive_summary.html",
            "findings.json",
            "chain.json",
            "attack_paths.md",
            "recommendations.md",
            "tenant.json",
            "run.json",
        ]:
            src = run_dir / artifact_name
            if src.exists():
                dst = root / artifact_name
                dst.write_bytes(src.read_bytes())

        chain_data: dict[str, Any] = {}
        chain_path = run_dir / "chain.json"
        if chain_path.exists():
            chain_data = json.loads(chain_path.read_text(encoding="utf-8"))

        counts = result.get("counts", {})
        snapshot = result.get("snapshot", {})

        await update_scan(
            run_id,
            status="completed",
            finished_at=datetime.now(timezone.utc).isoformat(),
            counts=counts,
            snapshot=snapshot,
            chain=chain_data,
        )
        await streamer.put(run_id, {"type": "scan_complete", "counts": counts})
    except Exception as e:
        await update_scan(run_id, status="failed", error=str(e))
        await streamer.put(run_id, {"type": "scan_error", "error": str(e)})
    finally:
        streamer.unregister(run_id)
