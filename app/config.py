"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"
    dns_nameserver: str | None = None
    dns_timeout_seconds: float = 3.0
    spamhaus_dqs_key: str | None = None
    enable_barracuda_brbl: bool = False


def _parse_bool(raw: str | None) -> bool:
    return (raw or "").strip().lower() in ("1", "true", "yes", "on")


def load_settings() -> Settings:
    nameserver = os.environ.get("DNS_NAMESERVER", "").strip() or None
    timeout_raw = os.environ.get("DNS_TIMEOUT_SECONDS", "3.0").strip()
    try:
        timeout = float(timeout_raw)
    except ValueError:
        timeout = 3.0
    if timeout <= 0:
        timeout = 3.0

    dqs_key = os.environ.get("SPAMHAUS_DQS_KEY", "").strip() or None

    return Settings(
        app_env=os.environ.get("APP_ENV", "development").strip() or "development",
        dns_nameserver=nameserver,
        dns_timeout_seconds=timeout,
        spamhaus_dqs_key=dqs_key,
        enable_barracuda_brbl=_parse_bool(os.environ.get("ENABLE_BARRACUDA_BRBL")),
    )
