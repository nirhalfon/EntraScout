# Web App

EntraScout ships with a **FastAPI + React** web console — a terminal-style recon dashboard for browser-based scanning.

## Features

- **5-view console layout** — Console, Findings, Attack Chains, Surface, History
- **Real-time SSE streaming** — watch phases execute live via probe stream
- **Command bar** — `$ scout target.com` monospace input with phase picker
- **Phase strip** — 52-cell progress grid (pending / running / done / error)
- **Severity dashboard** — CRITICAL / HIGH / MEDIUM / LOW / INFO bar chart + stat cards
- **Attack chain graph** — SVG bezier-curve visualization with effort levels and MITRE IDs
- **Surface heatmap** — findings grouped by category (Identity, M365, Azure, Power, Defense, DNS, OSINT, Endpoint)
- **Scan history** — table with reload, rerun, and delete actions
- **Live log feed** — scrolling monospace probe stream with severity coloring
- **Bloomberg-terminal aesthetic** — JetBrains Mono + Inter, dark ink palette, dense data-forward layout

## Running locally

```bash
docker-compose up --build
```

Open [http://localhost:8000](http://localhost:8000).

## Views

| View | Description |
|------|-------------|
| **Console** | Stats row, tenant fingerprint, DNS surface, live probe log, severity bars, report/exec/artifacts |
| **Findings** | Filterable severity table with group chips, phase IDs, expandable details |
| **Attack Chains** | SVG graph (target → chained primitives) + detail cards with MITRE ATT&CK references |
| **Surface** | Heatmap grid by group — finding density per category |
| **History** | Session scan log with reload and rerun |

## API

The web app exposes a REST API on `/api/*`. See [API Reference](api.md) for endpoints.

## Design System

| Element | Value |
|---------|-------|
| Base background | `#0a0e14` |
| Panel background | `#0f1521` |
| Log background | `#08090d` |
| Hairlines | `#1c2433` / `#243049` |
| Text | `#c9d1d9` |
| Muted | `#6b7280` / `#4a5568` |
| Severity colors | `oklch()` — red (critical), orange (high), yellow (medium), green (low), blue (info) |
| Fonts | JetBrains Mono (data/code), Inter (headings/UI) |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8000` | Server port |
| `ENTRASCOUT_DB` | `./data/entrascout.db` | SQLite database path |
| `ENTRASCOUT_OUTPUT` | `./web_output` | Scan artifact directory |
| `ENTRASCOUT_RATE_LIMIT` | `10` | Max scans per IP per hour |
| `ENTRASCOUT_RELOAD` | `false` | Uvicorn auto-reload (dev only) |