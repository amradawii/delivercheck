"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"
    dns_nameserver: str | None = None
    dns_timeout_seconds: float = 3.0


def load_settings() -> Settings:
    nameserver = os.environ.get("DNS_NAMESERVER", "").strip() or None
    timeout_raw = os.environ.get("DNS_TIMEOUT_SECONDS", "3.0").strip()
    try:
        timeout = float(timeout_raw)
    except ValueError:
        timeout = 3.0
    if timeout <= 0:
        timeout = 3.0

    return Settings(
        app_env=os.environ.get("APP_ENV", "development").strip() or "development",
        dns_nameserver=nameserver,
        dns_timeout_seconds=timeout,
    )
