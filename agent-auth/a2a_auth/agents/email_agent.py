"""Email agent: can draft and send, but sending needs a scope nobody is granted.

That is the point of the demo: even if the assistant were tricked (say, by a
prompt injection in a calendar invite) into trying to send email, the
authorization server would refuse to mint an ``email:send`` token for it.
"""

from __future__ import annotations

import httpx
from fastapi import Depends, FastAPI
from pydantic import BaseModel

from ..config import EMAIL_AGENT, Settings
from ..verifier import AccessTokenVerifier, Caller


class Email(BaseModel):
    to: list[str]
    subject: str
    body: str


def create_app(
    settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    settings = settings or Settings.from_env()
    verifier = AccessTokenVerifier(EMAIL_AGENT, settings, transport)
    drafts: list[dict] = []
    app = FastAPI(title="Email Agent")

    @app.post("/drafts", status_code=201)
    async def create_draft(email: Email, caller: Caller = Depends(verifier.require("email:draft"))):
        draft = email.model_dump() | {"id": len(drafts) + 1, "created_by": caller.agent_id}
        drafts.append(draft)
        return draft

    @app.post("/send")
    async def send(email: Email, caller: Caller = Depends(verifier.require("email:send"))):
        return {"status": "sent", "sent_by": caller.agent_id}

    return app
