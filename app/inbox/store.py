"""In-memory test inbox store with automatic 15-minute expiry (no database, no attachments)."""

from __future__ import annotations

import secrets
import string
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.inbox.analyze import EmailAnalysisReport

INBOX_TTL_SECONDS = 15 * 60.0  # 15 minutes
MAX_INBOX_SLOTS = 500
_TOKEN_ALPHABET = string.ascii_lowercase + string.digits


@dataclass
class InboxSlot:
    token: str
    address: str
    created_at: float
    expires_at: float
    analysis: EmailAnalysisReport | None = None

    @property
    def has_email(self) -> bool:
        return self.analysis is not None

    def seconds_remaining(self, now: float) -> int:
        return max(0, int(self.expires_at - now))


class InboxStore:
    """Single-process in-memory store for temporary test email addresses."""

    def __init__(
        self,
        domain: str = "test.localhost",
        *,
        ttl_seconds: float = INBOX_TTL_SECONDS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.domain = domain.strip().lower().rstrip(".")
        self._ttl_seconds = ttl_seconds
        self._clock = clock or time.monotonic
        self._slots: dict[str, InboxSlot] = {}

    def prune(self) -> None:
        now = self._clock()
        expired = [tok for tok, slot in self._slots.items() if now >= slot.expires_at]
        for tok in expired:
            self._slots.pop(tok, None)
        while len(self._slots) >= MAX_INBOX_SLOTS:
            oldest = next(iter(self._slots))
            self._slots.pop(oldest, None)

    def create_slot(self) -> InboxSlot:
        self.prune()
        now = self._clock()
        for _ in range(10):
            suffix = "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(8))
            token = f"t-{suffix}"
            if token not in self._slots:
                break
        address = f"{token}@{self.domain}"
        slot = InboxSlot(
            token=token,
            address=address,
            created_at=now,
            expires_at=now + self._ttl_seconds,
        )
        self._slots[token] = slot
        return slot

    def get(self, token: str) -> InboxSlot | None:
        self.prune()
        return self._slots.get(token.strip().lower())

    def match_recipient(self, rcpt_address: str) -> InboxSlot | None:
        """Return the active InboxSlot ONLY if rcpt_address matches a valid, unexpired token."""
        self.prune()
        cleaned = rcpt_address.strip().strip("<>").lower()
        local, sep, domain = cleaned.partition("@")
        if not sep or domain != self.domain:
            return None
        slot = self._slots.get(local)
        if slot is None:
            return None
        if self._clock() >= slot.expires_at:
            self._slots.pop(local, None)
            return None
        return slot

    def record_analysis(self, token: str, analysis: EmailAnalysisReport) -> bool:
        slot = self.get(token)
        if slot is None:
            return False
        slot.analysis = analysis
        return True

    def now(self) -> float:
        return self._clock()
