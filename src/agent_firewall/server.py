from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from agent_firewall.api.app import create_app


def create_server_app() -> FastAPI:
    return create_app()


def run() -> None:
    uvicorn.run("agent_firewall.server:create_server_app", factory=True, host="0.0.0.0", port=8000)
