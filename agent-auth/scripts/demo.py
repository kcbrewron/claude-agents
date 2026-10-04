"""A guided tour: the happy path, then five attacks that should all fail.

    python scripts/demo.py
"""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402
import jwt  # noqa: E402

from a2a_auth.client import AgentClient  # noqa: E402
from a2a_auth.config import ASSISTANT, CALENDAR_AGENT, EMAIL_AGENT  # noqa: E402
from a2a_auth.keys import bootstrap_keys  # noqa: E402
from a2a_auth.local_network import build_network  # noqa: E402


def step(title: str) -> None:
    print(f"\n=== {title} ===")


def show(resp: httpx.Response) -> None:
    print(f"  -> HTTP {resp.status_code}: {resp.json()}")


async def main() -> None:
    keys_dir = Path(tempfile.mkdtemp())
    settings, net, _ = build_network(keys_dir)
    user = httpx.AsyncClient(transport=net, base_url=settings.url_for(ASSISTANT))
    assistant = AgentClient(ASSISTANT, settings, net)

    step("1. You ask the assistant to schedule a meeting")
    show(await user.post("/schedule-meeting", json={
        "title": "Dentist", "start": "2026-10-10T09:00", "attendees": ["me@example.com"],
    }))

    step("2. You ask for your agenda")
    show(await user.get("/agenda"))

    step("3. Peek inside one access token the assistant received")
    token = await assistant.get_token(CALENDAR_AGENT, ["calendar:read"])
    for k, v in jwt.decode(token, options={"verify_signature": False}).items():
        print(f"  {k:10} {v}")

    step("ATTACK 1: assistant tries to SEND email (policy only allows drafts)")
    show(await user.post("/send-email", params={"to": "x@evil.test", "subject": "hi", "body": "!"}))

    step("ATTACK 2: a stolen token used as a plain Bearer token")
    raw = httpx.AsyncClient(transport=net)
    show(await raw.get(settings.url_for(CALENDAR_AGENT) + "/events",
                       headers={"Authorization": f"Bearer {token}"}))

    step("ATTACK 3: a stolen token used with the thief's own DPoP key")
    bootstrap_keys(keys_dir, ["thief"])
    thief = AgentClient("thief", settings, net)
    url = settings.url_for(CALENDAR_AGENT) + "/events"
    show(await raw.get(url, headers={"Authorization": f"DPoP {token}",
                                     "DPoP": thief.dpop_proof("GET", url, token)}))

    step("ATTACK 4: replaying a captured request (same token + same proof)")
    headers = {"Authorization": f"DPoP {token}", "DPoP": assistant.dpop_proof("GET", url, token)}
    print("  first use:", end="")
    show(await raw.get(url, headers=headers))
    print("  replay:   ", end="")
    show(await raw.get(url, headers=headers))

    step("ATTACK 5: calendar token presented to the email agent (wrong audience)")
    email_url = settings.url_for(EMAIL_AGENT) + "/drafts"
    show(await raw.post(email_url, json={"to": ["a@b.c"], "subject": "s", "body": "b"},
                        headers={"Authorization": f"DPoP {token}",
                                 "DPoP": assistant.dpop_proof("POST", email_url, token)}))

    step("ATTACK 6: an unregistered agent asks the auth server for a token")
    try:
        await thief.get_token(CALENDAR_AGENT, ["calendar:read"])
    except Exception as e:
        print(f"  -> refused: {e}")


if __name__ == "__main__":
    asyncio.run(main())
