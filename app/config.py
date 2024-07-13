"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"
    dns_nameserver: str | None = None
    dns_timeout_seconds: float = 3.0
    check_timeout_seconds: float = 12.0
    spamhaus_dqs_key: str | None = None
    enable_barracuda_brbl: bool = False
    smtp_inbox_enabled: bool = True
    smtp_inbox_host: str = "0.0.0.0"
    smtp_inbox_port: int = 2525
    test_inbox_domain: str = "test.localhost"
    smtp_inbox_tls_cert: str | None = None
    smtp_inbox_tls_key: str | None = None

    @property
    def is_local_inbox_domain(self) -> bool:
        d = self.test_inbox_domain.strip().lower().rstrip(".")
        return (
            d == "localhost"
            or d.endswith(".localhost")
            or d.endswith(".local")
            or d.endswith(".invalid")
        )


def _parse_bool(raw: str | None, *, default: bool = False) -> bool:
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def load_settings() -> Settings:
    nameserver = os.environ.get("DNS_NAMESERVER", "").strip() or None
    timeout_raw = os.environ.get("DNS_TIMEOUT_SECONDS", "3.0").strip()
    try:
        timeout = float(timeout_raw)
    except ValueError:
        timeout = 3.0
    if timeout <= 0:
        timeout = 3.0

    port_raw = os.environ.get("SMTP_INBOX_PORT", "2525").strip()
    try:
        inbox_port = int(port_raw)
    except ValueError:
        inbox_port = 2525

    check_timeout_raw = os.environ.get("CHECK_TIMEOUT_SECONDS", "12.0").strip()
    try:
        check_timeout = float(check_timeout_raw)
    except ValueError:
        check_timeout = 12.0
    if check_timeout <= 0:
        check_timeout = 12.0

    dqs_key = os.environ.get("SPAMHAUS_DQS_KEY", "").strip() or None
    inbox_domain = os.environ.get("TEST_INBOX_DOMAIN", "test.localhost").strip().lower()
    if not inbox_domain:
        inbox_domain = "test.localhost"

    return Settings(
        app_env=os.environ.get("APP_ENV", "development").strip() or "development",
        dns_nameserver=nameserver,
        dns_timeout_seconds=timeout,
        check_timeout_seconds=check_timeout,
        spamhaus_dqs_key=dqs_key,
        enable_barracuda_brbl=_parse_bool(os.environ.get("ENABLE_BARRACUDA_BRBL"), default=False),
        smtp_inbox_enabled=_parse_bool(os.environ.get("SMTP_INBOX_ENABLED"), default=True),
        smtp_inbox_host=os.environ.get("SMTP_INBOX_HOST", "0.0.0.0").strip() or "0.0.0.0",
        smtp_inbox_port=inbox_port,
        test_inbox_domain=inbox_domain,
        smtp_inbox_tls_cert=os.environ.get("SMTP_INBOX_TLS_CERT", "").strip() or None,
        smtp_inbox_tls_key=os.environ.get("SMTP_INBOX_TLS_KEY", "").strip() or None,
    )
