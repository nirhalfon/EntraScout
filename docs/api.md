# API Reference

The web backend exposes a REST API under `/api`.

## Health

```http
GET /api/health
```

Returns `{"status": "ok"}`.

## Phases

```http
GET /api/phases
```

Returns all 52 phases as JSON array.

## Scans

### Create scan

```http
POST /api/scans
Content-Type: application/json

{
  "target": "target.com",
  "phases": ["1", "2", "5"],
  "quick": false,
  "stealth": false,
  "internal": false,
  "timeout": 8.0,
  "workers": 32,
  "token": null,
  "bing_key": null,
  "user_hint": null
}
```

Returns `{"run_id": "..."}` immediately.

### List scans

```http
GET /api/scans?limit=50&offset=0
```

### Get scan

```http
GET /api/scans/{run_id}
```

### SSE events

```http
GET /api/scans/{run_id}/events
```

Server-Sent Events stream with `phase_start`, `phase_end`, `finding`, `scan_complete`, `scan_error`.

### Get findings

```http
GET /api/scans/{run_id}/findings
```

### Get chain

```http
GET /api/scans/{run_id}/chain
```

### Get report HTML

```http
GET /api/scans/{run_id}/report.html
```

### Get executive summary

```http
GET /api/scans/{run_id}/executive_summary.html
```

### Get artifact

```http
GET /api/scans/{run_id}/artifacts/{name}
```

Names: `findings.json`, `issues.json`, `leads.json`, `chain.json`, `attack_paths.md`, etc.

### Re-run scan

```http
POST /api/scans/{run_id}/rerun
```

Returns `{"run_id": "..."}` for the new scan.

### Delete scan

```http
DELETE /api/scans/{run_id}
```
