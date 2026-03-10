from __future__ import annotations

import asyncio

from agent_firewall.config import get_settings
from agent_firewall.container import Container


async def main() -> int:
    settings = get_settings()
    container = Container.build(settings=settings, use_in_memory=False)
    try:
        health = await container.dependency_health()
        print(f"postgres={health.postgres}")
        print(f"redis={health.redis}")
        return 0 if health.postgres and health.redis else 1
    finally:
        await container.shutdown()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
