# CLI Reference

## Usage

```bash
entrascout [OPTIONS] [TARGET]
```

## Arguments

| Argument | Description |
|---|---|
| `TARGET` | Domain to recon (e.g. `target.com`). Required unless `--list-phases` is used. |

## Options

| Option | Default | Description |
|---|---|---|
| `--internal` | `false` | Also run internal-mode probes |
| `--user` | — | Known user@domain to seed user-enum (e.g. `ceo@target.com`) |
| `--token` | — | Optional auth token (Graph PAT etc). Never written to disk |
| `--bing-key` | — | Bing Web Search API key for automated dorks |
| `--output` | `./output` | Where to write the per-run output folder |
| `--quick` | `false` | Faster scan with reduced coverage |
| `--stealth` | `false` | Stealth mode: low QPS + jitter + randomized order |
| `--phases` | — | Comma-separated phase numbers OR names |
| `--list-phases` | `false` | Print all phases and exit |
| `--timeout` | `8.0` | Per-request timeout (seconds) |
| `--workers` | `32` | Concurrent workers |
| `--proxy` | — | Proxy URL (e.g. `socks5://127.0.0.1:9050`) |
| `--log-level` | `DEBUG` | Console + file log level |
| `--no-banner` | `false` | Suppress the banner |

## Environment Variables

| Variable | Maps to | Description |
|---|---|---|
| `ENTRASCOUT_TOKEN` | `--token` | Auth token |
| `BING_API_KEY` | `--bing-key` | Bing API key |

## Examples

```bash
# Full scan
entrascout target.com

# Internal + user hint
entrascout target.com --internal --user ceo@target.com

# Quick preset phases
entrascout target.com --phases 1,2,29

# By name
entrascout target.com --phases tenant,federation,sharepoint_recon

# List all phases
entrascout --list-phases
```
