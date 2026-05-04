"""Uvicorn entry point for the web app."""
from __future__ import annotations

import os

import uvicorn

from .api import app


def main() -> None:
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(
        "entrascout.web.api:app",
        host="0.0.0.0",
        port=port,
        reload=os.environ.get("ENTRASCOUT_RELOAD", "").lower() == "true",
    )


if __name__ == "__main__":
    main()
