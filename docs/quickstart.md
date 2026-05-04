# Quick Start

## Installation

Requires **Python 3.10+**.

```bash
pip install entrascout
```

Or install from source:

```bash
git clone https://github.com/assor17/entrascout.git
cd entrascout
pip install -e "."
```

## First Scan

```bash
entrascout target.com
```

This runs the default external recon suite and writes results to `./output/`.

## Quick Options

```bash
# Faster scan with reduced coverage
entrascout target.com --quick

# Stealth mode (low QPS + jitter)
entrascout target.com --stealth

# Internal-mode probes (assume corp-net foothold)
entrascout target.com --internal

# Select specific phases
entrascout target.com --phases tenant,federation,sharepoint_recon

# Authenticated Graph pass
entrascout target.com --token $GRAPH_TOKEN
```

## Web App

```bash
docker-compose up --build
```

Open [http://localhost:8000](http://localhost:8000).

See [Web App](web-app.md) for full details.
