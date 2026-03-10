from __future__ import annotations

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
        self._counts: dict[str, int] = {}

    async def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        del window_seconds
        current = self._counts.get(key, 0) + 1
        self._counts[key] = current
        remaining = max(limit - current, 0)
        return current <= limit, remaining

