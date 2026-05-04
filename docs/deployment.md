# Deployment

## Docker (Recommended)

```bash
docker-compose up --build
```

Single container with:
- FastAPI backend
- React frontend (served as static files)
- SQLite persistence (volume `./data`)

## Render

1. Connect your GitHub repo to Render
2. Select "Web Service"
3. Render auto-detects the `Dockerfile`
4. Set environment variables:
   - `ENTRASCOUT_DB=/app/data/entrascout.db`
   - `ENTRASCOUT_OUTPUT=/app/data/output`
   - `ENTRASCOUT_RATE_LIMIT=10`
5. Add a disk mount at `/app/data`

Or use the `render.yaml` blueprint:

```bash
# Already included in repo — Render will auto-detect
```

## Railway

```bash
railway up
```

Uses `railway.json` configuration.

## Fly.io

```bash
fly launch
cd entrascout  # from repo root
```

## Vercel (Frontend only)

The backend requires long-running tasks (>5 min), which exceeds Vercel's serverless timeout. Deploy the frontend separately only if you have an external backend:

```bash
cd frontend
vercel --prod
```

Set `NEXT_PUBLIC_API_URL` to your backend URL.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8000` | Server port |
| `ENTRASCOUT_DB` | `./data/entrascout.db` | SQLite path |
| `ENTRASCOUT_OUTPUT` | `./web_output` | Artifact directory |
| `ENTRASCOUT_RATE_LIMIT` | `10` | Scans per IP per hour |
| `ENTRASCOUT_RELOAD` | `false` | Dev auto-reload |
