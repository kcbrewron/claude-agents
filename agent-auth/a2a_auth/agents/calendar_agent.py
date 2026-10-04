"""Calendar agent: owns the calendar and only trusts verified callers."""

from __future__ import annotations

import httpx
from fastapi import Depends, FastAPI
from pydantic import BaseModel

from ..config import CALENDAR_AGENT, Settings
from ..verifier import AccessTokenVerifier, Caller


class NewEvent(BaseModel):
    title: str
    start: str
    attendees: list[str] = []


def create_app(
    settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    settings = settings or Settings.from_env()
    verifier = AccessTokenVerifier(CALENDAR_AGENT, settings, transport)
    events: list[dict] = []
    app = FastAPI(title="Calendar Agent")

    @app.get("/events")
    async def list_events(caller: Caller = Depends(verifier.require("calendar:read"))):
        return {"events": events, "served_to": caller.agent_id}

    @app.post("/events", status_code=201)
    async def add_event(
        event: NewEvent, caller: Caller = Depends(verifier.require("calendar:write"))
    ):
        record = event.model_dump() | {"id": len(events) + 1, "created_by": caller.agent_id}
        events.append(record)
        return record

    return app
