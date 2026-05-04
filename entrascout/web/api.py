"""FastAPI app for EntraScout web."""
from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from ..checks import PHASES
from ..cli import _phase_descriptions
from .runner_wrapper import run_scan_background
from .schemas import PhaseInfo, ScanCreateRequest
from .store import (
    add_finding,
    create_scan,
    delete_scan,
    get_findings,
    get_scan,
    init_db,
    list_scans,
    update_scan,
)
from .streamer import ScanStreamer

STREAMER = ScanStreamer()
RATE_LIMITS: dict[str, list[float]] = {}
MAX_SCANS_PER_HOUR = int(os.environ.get("ENTRASCOUT_RATE_LIMIT", "10"))
WEB_OUTPUT_ROOT = os.environ.get("ENTRASCOUT_OUTPUT", "./web_output")


def _check_rate_limit(ip: str) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    window = [t for t in RATE_LIMITS.get(ip, []) if now - t < 3600]
    RATE_LIMITS[ip] = window
    if len(window) >= MAX_SCANS_PER_HOUR:
        return False
    window.append(now)
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="EntraScout Web", version="0.1.8", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(_static_dir / "assets"), check_dir=False), name="assets")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/phases")
async def phases() -> list[PhaseInfo]:
    descs = _phase_descriptions()
    out: list[PhaseInfo] = []
    keys = list(PHASES.keys())
    keys.sort(key=lambda k: (1, k) if not k.isdigit() else (0, int(k)))
    for k in keys:
        name, _ = PHASES[k]
        out.append(PhaseInfo(id=k, name=name, description=descs.get(name, "")))
    return out


@app.post("/api/scans")
async def create_scan_endpoint(req: ScanCreateRequest, request: Request) -> dict[str, str]:
    ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 10 scans per hour")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + os.urandom(4).hex()
    options = req.model_dump()
    await create_scan(run_id, req.target, "pending", options)
    asyncio.create_task(run_scan_background(run_id, options, STREAMER))
    return {"run_id": run_id}


@app.get("/api/scans")
async def list_scans_endpoint(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    rows = await list_scans(limit, offset)
    return [_scan_row_to_response(r) for r in rows]


@app.get("/api/scans/{run_id}")
async def get_scan_endpoint(run_id: str) -> dict[str, Any]:
    row = await get_scan(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_row_to_response(row)


@app.get("/api/scans/{run_id}/events")
async def scan_events(run_id: str) -> StreamingResponse:
    row = await get_scan(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    q = STREAMER.register(run_id)

    async def event_generator() -> Any:
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=25.0)
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
                    continue
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ("scan_complete", "scan_error"):
                    break
        finally:
            STREAMER.unregister(run_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/scans/{run_id}/findings")
async def get_findings_endpoint(run_id: str) -> list[dict[str, Any]]:
    return await get_findings(run_id)


@app.get("/api/scans/{run_id}/chain")
async def get_chain_endpoint(run_id: str) -> dict[str, Any]:
    row = await get_scan(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    chain = row.get("chain")
    if chain:
        return json.loads(chain) if isinstance(chain, str) else chain
    return {}


@app.get("/api/scans/{run_id}/report.html")
async def get_report_html(run_id: str) -> HTMLResponse:
    path = Path(WEB_OUTPUT_ROOT) / run_id / "report.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not ready")
    return HTMLResponse(content=path.read_text(encoding="utf-8"))


@app.get("/api/scans/{run_id}/executive_summary.html")
async def get_exec_summary_html(run_id: str) -> HTMLResponse:
    path = Path(WEB_OUTPUT_ROOT) / run_id / "executive_summary.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Summary not ready")
    return HTMLResponse(content=path.read_text(encoding="utf-8"))


@app.get("/api/scans/{run_id}/artifacts/{name}")
async def get_artifact(run_id: str, name: str) -> FileResponse:
    path = Path(WEB_OUTPUT_ROOT) / run_id / name
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(str(path))


@app.delete("/api/scans/{run_id}")
async def delete_scan_endpoint(run_id: str) -> dict[str, str]:
    await delete_scan(run_id)
    return {"deleted": run_id}


@app.post("/api/scans/{run_id}/rerun")
async def rerun_scan(run_id: str) -> dict[str, str]:
    row = await get_scan(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    options = json.loads(row["options"])
    new_run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + os.urandom(4).hex()
    await create_scan(new_run_id, row["target"], "pending", options)
    asyncio.create_task(run_scan_background(new_run_id, options, STREAMER))
    return {"run_id": new_run_id}


def _scan_row_to_response(row: dict[str, Any]) -> dict[str, Any]:
    counts = row.get("counts")
    snapshot = row.get("snapshot")
    return {
        "run_id": row["run_id"],
        "target": row["target"],
        "status": row["status"],
        "started_at": row["started_at"],
        "finished_at": row.get("finished_at"),
        "counts": json.loads(counts) if counts and isinstance(counts, str) else counts,
        "snapshot": json.loads(snapshot) if snapshot and isinstance(snapshot, str) else snapshot,
        "error": row.get("error"),
    }


# Serve frontend index.html for root and any unmatched paths
@app.get("/")
@app.get("/{full_path:path}")
async def serve_frontend(full_path: str = "") -> HTMLResponse:
    index_path = _static_dir / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>EntraScout API is running.</h1><p>Build the frontend to see the UI.</p>")
