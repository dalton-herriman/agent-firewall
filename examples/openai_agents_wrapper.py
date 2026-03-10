from __future__ import annotations

import asyncio

from agent_firewall import guard_openai_tool
from examples.shared import build_demo_sdk


@guard_openai_tool(sdk=build_demo_sdk(), agent_id="demo-agent", tool_name="weather.lookup")
async def weather_lookup(city: str) -> dict[str, str]:
    return {"city": city, "forecast": "clear"}


if __name__ == "__main__":
    print(asyncio.run(weather_lookup(city="Chicago")))

