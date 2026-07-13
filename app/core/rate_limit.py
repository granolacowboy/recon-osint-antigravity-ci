from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque


class RateLimitError(RuntimeError):
    """The rate-limiter dependency is unavailable."""


class RateLimiter(ABC):
    @abstractmethod
    async def health(self) -> bool: ...

    @abstractmethod
    async def allow(self, principal_id: str, *, cost: int = 1) -> bool: ...

    @abstractmethod
    async def close(self) -> None: ...


class InMemoryRateLimiter(RateLimiter):
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("rate limit values must be positive")
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def health(self) -> bool:
        return True

    async def allow(self, principal_id: str, *, cost: int = 1) -> bool:
        if cost < 1:
            raise ValueError("rate-limit cost must be positive")
        now = time.monotonic()
        threshold = now - self._window_seconds
        async with self._lock:
            bucket = self._requests[principal_id]
            while bucket and bucket[0] <= threshold:
                bucket.popleft()
            if len(bucket) + cost > self._max_requests:
                return False
            bucket.extend(now for _ in range(cost))
            return True

    async def close(self) -> None:
        self._requests.clear()


class RedisRateLimiter(RateLimiter):
    """Fixed-window Redis limiter shared across API processes."""

    _SCRIPT = """
    local current = redis.call('INCRBY', KEYS[1], ARGV[2])
    if current == tonumber(ARGV[2]) then
      redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return current
    """

    def __init__(
        self,
        redis_client: object,
        max_requests: int,
        window_seconds: int,
        *,
        owns_client: bool = True,
    ) -> None:
        self._redis = redis_client
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._owns_client = owns_client

    async def health(self) -> bool:
        try:
            return bool(await self._redis.ping())
        except Exception:
            return False

    async def allow(self, principal_id: str, *, cost: int = 1) -> bool:
        if cost < 1:
            raise ValueError("rate-limit cost must be positive")
        bucket = int(time.time()) // self._window_seconds
        key = f"recon:rate:{principal_id}:{bucket}"
        try:
            count = await self._redis.eval(
                self._SCRIPT, 1, key, self._window_seconds, cost
            )
        except Exception as exc:
            raise RateLimitError("rate limiter is unavailable") from exc
        return int(count) <= self._max_requests

    async def close(self) -> None:
        if not self._owns_client:
            return
        close = getattr(self._redis, "aclose", None)
        if close is not None:
            await close()
