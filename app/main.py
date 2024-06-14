"""FastAPI application entrypoint."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.checks.extras import PolicyFetcher
from app.config import Settings, load_settings
from app.dns.resolver import AsyncDNSResolver, DNSResolver
from app.limits import RateLimiter
from app.web.routes import router as web_router
from app.web.state import DomainSessionStore

STATIC_DIR = Path(__file__).resolve().parent / "web" / "static"


def create_app(
    settings: Settings | None = None,
    *,
    resolver: DNSResolver | None = None,
    rate_limiter: RateLimiter | None = None,
    policy_fetcher: PolicyFetcher | None = None,
) -> FastAPI:
    resolved_settings = settings or load_settings()
    resolved_dns: DNSResolver = resolver or AsyncDNSResolver(
        nameserver=resolved_settings.dns_nameserver,
        timeout_seconds=resolved_settings.dns_timeout_seconds,
    )

    application = FastAPI(
        title="DeliverCheck",
        description="Check if a domain's email is ready to send and receive, and how to fix it.",
        version="0.1.0",
    )
    application.state.settings = resolved_settings
    application.state.resolver = resolved_dns
    application.state.rate_limiter = rate_limiter or RateLimiter()
    application.state.domain_sessions = DomainSessionStore()
    application.state.policy_fetcher = policy_fetcher

    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    application.include_router(web_router)

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
