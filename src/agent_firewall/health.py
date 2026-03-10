from __future__ import annotations

from dataclasses import dataclass

from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


@dataclass(slots=True)
class DependencyHealth:
    postgres: bool
    redis: bool


async def check_postgres(engine: AsyncEngine | None) -> bool:
    if engine is None:
        return False
    try:
        async with engine.connect() as connection:
            await connection.execute(text("select 1"))
        return True
    except Exception:
        return False


async def check_redis(redis: Redis | None) -> bool:
    if redis is None:
        return False
    try:
        pong = await redis.ping()
        return bool(pong)
    except Exception:
        return False


async def check_dependencies(engine: AsyncEngine | None, redis: Redis | None) -> DependencyHealth:
    return DependencyHealth(
        postgres=await check_postgres(engine),
        redis=await check_redis(redis),
    )
