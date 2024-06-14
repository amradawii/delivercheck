"""In-memory per-IP sliding-window rate limiter with stricter limits for live probes."""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitRule:
    max_requests: int
    window_seconds: float


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: int


DEFAULT_RATE_LIMITS: dict[str, RateLimitRule] = {
    "domain": RateLimitRule(max_requests=30, window_seconds=60.0),
    "server": RateLimitRule(max_requests=6, window_seconds=60.0),
    "send": RateLimitRule(max_requests=3, window_seconds=60.0),
    "inbox": RateLimitRule(max_requests=10, window_seconds=60.0),
}


class RateLimiter:
    """Simple thread/asyncio-safe single-process sliding-window limiter."""

    def __init__(
        self,
        rules: dict[str, RateLimitRule] | None = None,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._rules = dict(DEFAULT_RATE_LIMITS)
        if rules:
            self._rules.update(rules)
        self._clock = clock or time.monotonic
        self._buckets: dict[tuple[str, str], deque[float]] = {}

    def check(self, bucket: str, client_key: str) -> RateLimitDecision:
        rule = self._rules.get(bucket)
        if rule is None:
            return RateLimitDecision(allowed=True, remaining=999, retry_after_seconds=0)

        now = self._clock()
        cutoff = now - rule.window_seconds
        key = (bucket, client_key or "unknown")

        timestamps = self._buckets.get(key)
        if timestamps is None:
            timestamps = deque()
            self._buckets[key] = timestamps

        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        if len(timestamps) >= rule.max_requests:
            oldest = timestamps[0]
            retry_after = max(1, int(rule.window_seconds - (now - oldest)) + 1)
            return RateLimitDecision(
                allowed=False,
                remaining=0,
                retry_after_seconds=retry_after,
            )

        timestamps.append(now)
        remaining = max(0, rule.max_requests - len(timestamps))
        return RateLimitDecision(allowed=True, remaining=remaining, retry_after_seconds=0)

    def reset(self) -> None:
        self._buckets.clear()
