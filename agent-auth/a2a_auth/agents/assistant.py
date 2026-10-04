"""The personal assistant: the agent you talk to, which delegates to the others.

Note it holds *no* calendar or email credentials of its own.  For every call it
asks the authorization server for a narrow, short-lived token for exactly the
agent and scopes it needs right now.

The user-facing endpoints here are unauthenticated and the service binds to
127.0.0.1 by default.  Authenticating *you* to the assistant (passkeys, OAuth
login) is a separate problem from agent-to-agent auth -- see the README.
"""

from __future__ import annotations

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..client import AgentClient, TokenRequestError
from ..config import ASSISTANT, CALENDAR_AGENT, EMAIL_AGENT, Settings


class MeetingRequest(BaseModel):
    title: str
    start: str
    attendees: list[str]


def create_app(
    settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    settings = settings or Settings.from_env()
    agent = AgentClient(ASSISTANT, settings, transport)
    app = FastAPI(title="Personal Assistant")

    async def call(method: str, audience: str, path: str, scopes: list[str], **kwargs) -> dict:
        try:
            resp = await agent.request(method, audience, path, scopes, **kwargs)
        except TokenRequestError as e:
            # The AS said no -- surface that instead of pretending it worked.
            raise HTTPException(403, {"denied_by": "auth-server", **e.body})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, {"denied_by": audience, **resp.json()})
        return resp.json()

    @app.get("/agenda")
    async def agenda():
        return await call("GET", CALENDAR_AGENT, "/events", ["calendar:read"])

    @app.post("/schedule-meeting")
    async def schedule_meeting(req: MeetingRequest):
        event = await call(
            "POST", CALENDAR_AGENT, "/events", ["calendar:write"], json=req.model_dump()
        )
        draft = await call(
            "POST",
            EMAIL_AGENT,
            "/drafts",
            ["email:draft"],
            json={
                "to": req.attendees,
                "subject": f"Invitation: {req.title}",
                "body": f"You're invited to '{req.title}' at {req.start}.",
            },
        )
        return {"event": event, "invite_draft": draft}

    @app.post("/send-email")
    async def send_email(to: str, subject: str, body: str):
        # Exists only to show the policy refusing a scope the assistant lacks.
        return await call(
            "POST", EMAIL_AGENT, "/send", ["email:send"],
            json={"to": [to], "subject": subject, "body": body},
        )

    return app
