"""FastAPI application entrypoint with in-process SMTP test inbox lifespan."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.checks.extras import PolicyFetcher
from app.config import Settings, load_settings
from app.dns.resolver import AsyncDNSResolver, DNSResolver
from app.inbox.server import InboxSMTPServer
from app.inbox.store import InboxStore
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
    inbox_store: InboxStore | None = None,
    enable_smtp_inbox: bool | None = None,
) -> FastAPI:
    resolved_settings = settings or load_settings()
    resolved_dns: DNSResolver = resolver or AsyncDNSResolver(
        nameserver=resolved_settings.dns_nameserver,
        timeout_seconds=resolved_settings.dns_timeout_seconds,
    )
    resolved_inbox_store = inbox_store or InboxStore(domain=resolved_settings.test_inbox_domain)
    start_smtp = (
        resolved_settings.smtp_inbox_enabled if enable_smtp_inbox is None else enable_smtp_inbox
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        smtp_server: InboxSMTPServer | None = None
        if start_smtp:
            smtp_server = InboxSMTPServer(
                store=resolved_inbox_store,
                resolver=resolved_dns,
                host=resolved_settings.smtp_inbox_host,
                port=resolved_settings.smtp_inbox_port,
                tls_cert=resolved_settings.smtp_inbox_tls_cert,
                tls_key=resolved_settings.smtp_inbox_tls_key,
            )
            smtp_server.start()
            application.state.smtp_inbox_server = smtp_server
        try:
            yield
        finally:
            if smtp_server is not None:
                smtp_server.stop()
                application.state.smtp_inbox_server = None

    application = FastAPI(
        title="DeliverCheck",
        description="Check if a domain's email is ready to send and receive, and how to fix it.",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.resolver = resolved_dns
    application.state.rate_limiter = rate_limiter or RateLimiter()
    application.state.domain_sessions = DomainSessionStore()
    application.state.policy_fetcher = policy_fetcher
    application.state.inbox_store = resolved_inbox_store
    application.state.smtp_inbox_server = None

    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    application.include_router(web_router)

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()
