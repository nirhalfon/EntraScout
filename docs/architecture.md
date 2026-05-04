# Architecture

## Overview

```
CLI (cli.py)
   ↓
runner.run_engagement()
   ├── RunContext, TenantSnapshot, OutputManager, StealthClient
   ├── loops over PHASES dict in dependency order
   │      └── each phase module.run(ctx, http, snap, om) → list[Finding]
   ├── om.add(finding)  (hydrates chain tags)
   ├── chain = build_chain(om.findings, target)
   ├── om.finalize(ctx, snap)  → JSON/CSV/MD artifacts
   └── report.render_html() + render_exec_summary()  → HTML
```

## Core Components

| File | Role |
|------|------|
| `cli.py` | Click CLI entry point |
| `runner.py` | Phase orchestrator (sequential loop) |
| `models.py` | Pydantic models: `Finding`, `TenantSnapshot`, `RunContext` |
| `output.py` | `OutputManager` — artifact writer |
| `report.py` | Jinja2 HTML renderer |
| `http_client.py` | `StealthClient` — async httpx with QPS throttle |
| `dns_client.py` | dnspython async wrappers |
| `chain/pathfinder.py` | Attack-path graph builder |
| `checks/__init__.py` | Phase registry (`PHASES` dict) |

## Phase Contract

Every phase exports:

```python
async def run(ctx: RunContext, http: StealthClient, snap: TenantSnapshot, om: OutputManager) -> list[Finding]
```

Phases communicate via the mutable `TenantSnapshot` and return `Finding` objects.

## Web Layer

| File | Role |
|------|------|
| `web/api.py` | FastAPI app, routes, CORS |
| `web/store.py` | Async SQLite persistence |
| `web/streamer.py` | SSE broadcaster |
| `web/runner_wrapper.py` | Background task wrapper |
| `web/schemas.py` | Pydantic request/response models |

## Data Flow (Web)

1. `POST /api/scans` → creates DB row, starts `asyncio.create_task(run_scan_background(...))`
2. `run_scan_background` uses `StreamingOutputManager` with an `event_callback`
3. Callback pushes to `ScanStreamer` queue
4. `GET /api/scans/{id}/events` subscribes to the queue and streams SSE

## Frontend Architecture

The web console is a React + Vite + Tailwind app (`frontend/`).

| Path | Role |
|------|------|
| `frontend/src/App.tsx` | Root component, 5-tab routing, App-level scan state via hooks |
| `frontend/src/hooks/useScanEvents.ts` | SSE subscription hook — returns `{ phases, findings, counts, status, error, logs }` |
| `frontend/src/hooks/useScanChain.ts` | Chain data polling hook |
| `frontend/src/hooks/usePhases.ts` | Phase list fetch hook |
| `frontend/src/components/ConsoleLayout.tsx` | Shell: sticky topbar with 5 tabs + status indicator |
| `frontend/src/components/CommandBar.tsx` | `$ scout target` input + phase picker + execute/cancel |
| `frontend/src/components/ui/*` | Shared primitives: SevPill, GroupChip, Panel, PhaseStrip, LogFeed, Stat, SevBars, Sparkline |
| `frontend/src/views/ConsoleView.tsx` | Live scan view: stats, tenant fingerprint, DNS panel, log feed, severity bars |
| `frontend/src/views/FindingsView.tsx` | Filterable findings table with severity tabs |
| `frontend/src/views/ChainsView.tsx` | SVG attack chain graph + detail cards |
| `frontend/src/views/SurfaceView.tsx` | Category heatmap grid |
| `frontend/src/views/HistoryView.tsx` | Scan history table |

### Design system

- **Palette**: `#0a0e14` base, `#0f1521` panels, `#1c2433`/`#243049` hairlines
- **Typography**: JetBrains Mono (body/data), Inter (headings)
- **Severity colors**: `oklch()` with hex fallbacks — critical (red), high (orange), medium (yellow), low (green), info (blue)
- **Aesthetic**: Bloomberg-terminal, dense, data-forward, no glass/blur effects
