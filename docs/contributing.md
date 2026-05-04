# Contributing

## Adding a New Phase

1. Create a new module in `entrascout/checks/`
2. Export an `async def run(ctx, http, snap, om)` function
3. Return a list of `Finding` objects
4. Register the phase in `entrascout/checks/__init__.py`

## Finding Factory

Use the helper factories from `checks._helpers`:

```python
from entrascout.checks._helpers import lead, issue, data, validation

return [
    issue(
        phase="my_phase",
        check="my_check",
        title="Something is exposed",
        severity=Severity.HIGH,
        target="target.com",
        description="...",
        tags=[ChainTag.AZ_BLOB_PUBLIC_LISTING],
        recommendation="Disable public access",
    ),
]
```

## Chain Tags

If your finding enables new attack primitives:

1. Add a `ChainTag` value in `models.py`
2. Map it in `TAG_ENABLES`
3. Add MITRE IDs in `TAG_MITRE`

## Tests

```bash
pytest tests/ -v
```

## Code Style

```bash
ruff check entrascout/
ruff format entrascout/
```
