"""FastAPI application entrypoint."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import Settings, load_settings
from app.web.routes import router as web_router

STATIC_DIR = Path(__file__).resolve().parent / "web" / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or load_settings()

    application = FastAPI(
        title="DeliverCheck",
        description="Check if a domain's email is ready to send and receive, and how to fix it.",
        version="0.1.0",
    )
    application.state.settings = resolved_settings

    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    application.include_router(web_router)

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
