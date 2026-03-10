from __future__ import annotations

from time import monotonic
from typing import Protocol

from redis.asyncio import Redis


class RateLimiter(Protocol):
    async def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        ...


class RedisRateLimiter:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        current = await self._redis.incr(key)
        if current == 1:
            await self._redis.expire(key, window_seconds)
        remaining = max(limit - current, 0)
        return current <= limit, remaining


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._counts: dict[str, tuple[int, float]] = {}

    async def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = monotonic()
        count, reset_at = self._counts.get(key, (0, now + window_seconds))
        if now >= reset_at:
            count = 0
            reset_at = now + window_seconds
        current = count + 1
        self._counts[key] = (current, reset_at)
        remaining = max(limit - current, 0)
        return current <= limit, remaining
