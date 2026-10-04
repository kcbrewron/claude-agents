"""Each test pins down one security property of the agent-to-agent protocol."""

import asyncio
import time

import httpx
import jwt
import pytest

from a2a_auth.auth_server import CLIENT_ASSERTION_TYPE
from a2a_auth.client import AgentClient, TokenRequestError
from a2a_auth.config import ASSISTANT, AUTH_SERVER, CALENDAR_AGENT, EMAIL_AGENT
from a2a_auth.keys import bootstrap_keys, load_private_key, private_key_path
from a2a_auth.local_network import build_network


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def env(tmp_path):
    settings, net, _ = build_network(tmp_path)
    return settings, net, AgentClient(ASSISTANT, settings, net)


def events_url(settings):
    return settings.url_for(CALENDAR_AGENT) + "/events"


async def raw_get(net, url, headers):
    async with httpx.AsyncClient(transport=net) as c:
        return await c.get(url, headers=headers)


# --- happy path -------------------------------------------------------------

def test_assistant_schedules_meeting_through_other_agents(env):
    settings, net, _ = env

    async def go():
        async with httpx.AsyncClient(transport=net, base_url=settings.url_for(ASSISTANT)) as user:
            r = await user.post("/schedule-meeting", json={
                "title": "Lunch", "start": "2026-10-05T12:00", "attendees": ["a@example.com"]})
            assert r.status_code == 200, r.text
            assert r.json()["event"]["created_by"] == "assistant"
            assert r.json()["invite_draft"]["created_by"] == "assistant"
            agenda = await user.get("/agenda")
            assert [e["title"] for e in agenda.json()["events"]] == ["Lunch"]

    run(go())


def test_token_is_audience_scoped_and_key_bound(env):
    _, _, assistant = env
    token = run(assistant.get_token(CALENDAR_AGENT, ["calendar:read"]))
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == CALENDAR_AGENT
    assert claims["scope"] == "calendar:read"
    assert claims["cnf"]["jkt"] == assistant._jwk["kid"]
    assert claims["exp"] - claims["iat"] <= 300


# --- authorization server ----------------------------------------------------

def test_policy_denies_scope_not_granted(env):
    _, _, assistant = env
    with pytest.raises(TokenRequestError) as e:
        run(assistant.get_token(EMAIL_AGENT, ["email:send"]))
    assert e.value.body["error"] == "invalid_scope"


def test_policy_denies_unlisted_target(env):
    settings, net, _ = env
    calendar = AgentClient(CALENDAR_AGENT, settings, net)
    with pytest.raises(TokenRequestError) as e:
        run(calendar.get_token(EMAIL_AGENT, ["email:draft"]))
    assert e.value.body["error"] == "invalid_target"


def test_unregistered_agent_is_rejected(env):
    settings, net, _ = env
    bootstrap_keys(settings.keys_dir, ["rogue"])
    with pytest.raises(TokenRequestError) as e:
        run(AgentClient("rogue", settings, net).get_token(CALENDAR_AGENT, ["calendar:read"]))
    assert e.value.body["error"] == "invalid_client"


def test_impersonation_with_wrong_key_is_rejected(env):
    """A rogue signs an assertion claiming to be the assistant."""
    settings, net, _ = env
    bootstrap_keys(settings.keys_dir, ["rogue"])
    rogue_key = load_private_key(private_key_path(settings.keys_dir, "rogue"))
    now = int(time.time())
    forged = jwt.encode({"iss": ASSISTANT, "sub": ASSISTANT, "aud": settings.issuer,
                         "iat": now, "exp": now + 60, "jti": "x"}, rogue_key, algorithm="EdDSA")

    async def go():
        async with httpx.AsyncClient(transport=net) as c:
            return await c.post(settings.token_endpoint, data={
                "grant_type": "client_credentials", "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": forged, "resource": CALENDAR_AGENT, "scope": "calendar:read"})

    r = run(go())
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_client_assertion_cannot_be_replayed(env):
    settings, net, assistant = env
    assertion = assistant.client_assertion()
    form = {"grant_type": "client_credentials", "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion, "resource": CALENDAR_AGENT, "scope": "calendar:read"}

    async def go():
        async with httpx.AsyncClient(transport=net) as c:
            first = await c.post(settings.token_endpoint, data=form)
            second = await c.post(settings.token_endpoint, data=form)
            return first, second

    first, second = run(go())
    assert first.status_code == 200
    assert second.status_code == 401
    assert "already used" in second.json()["error_description"]


# --- resource server (the called agent) ---------------------------------------

def test_bearer_without_proof_is_rejected(env):
    settings, net, assistant = env
    token = run(assistant.get_token(CALENDAR_AGENT, ["calendar:read"]))
    r = run(raw_get(net, events_url(settings), {"Authorization": f"Bearer {token}"}))
    assert r.status_code == 401


def test_stolen_token_with_thiefs_key_is_rejected(env):
    settings, net, assistant = env
    bootstrap_keys(settings.keys_dir, ["thief"])
    thief = AgentClient("thief", settings, net)
    token = run(assistant.get_token(CALENDAR_AGENT, ["calendar:read"]))
    url = events_url(settings)
    r = run(raw_get(net, url, {"Authorization": f"DPoP {token}",
                               "DPoP": thief.dpop_proof("GET", url, token)}))
    assert r.status_code == 401
    assert "does not match" in r.json()["detail"]["error_description"]


def test_replayed_proof_is_rejected(env):
    settings, net, assistant = env
    token = run(assistant.get_token(CALENDAR_AGENT, ["calendar:read"]))
    url = events_url(settings)
    headers = {"Authorization": f"DPoP {token}", "DPoP": assistant.dpop_proof("GET", url, token)}
    assert run(raw_get(net, url, headers)).status_code == 200
    assert run(raw_get(net, url, headers)).status_code == 401


def test_proof_for_another_url_is_rejected(env):
    settings, net, assistant = env
    token = run(assistant.get_token(CALENDAR_AGENT, ["calendar:read"]))
    proof = assistant.dpop_proof("GET", settings.url_for(CALENDAR_AGENT) + "/other", token)
    r = run(raw_get(net, events_url(settings), {"Authorization": f"DPoP {token}", "DPoP": proof}))
    assert r.status_code == 401


def test_token_for_other_audience_is_rejected(env):
    settings, net, assistant = env
    token = run(assistant.get_token(EMAIL_AGENT, ["email:draft"]))
    url = events_url(settings)
    r = run(raw_get(net, url, {"Authorization": f"DPoP {token}",
                               "DPoP": assistant.dpop_proof("GET", url, token)}))
    assert r.status_code == 401


def test_insufficient_scope_returns_403(env):
    settings, net, assistant = env

    async def go():
        token = await assistant.get_token(CALENDAR_AGENT, ["calendar:read"])
        url = events_url(settings)
        async with httpx.AsyncClient(transport=net) as c:
            return await c.post(url, json={"title": "x", "start": "y"}, headers={
                "Authorization": f"DPoP {token}", "DPoP": assistant.dpop_proof("POST", url, token)})

    r = run(go())
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "insufficient_scope"


def test_expired_token_is_rejected(env):
    settings, net, assistant = env
    as_key = load_private_key(private_key_path(settings.keys_dir, AUTH_SERVER))
    real_token = run(assistant.get_token(CALENDAR_AGENT, ["calendar:read"]))
    claims = jwt.decode(real_token, options={"verify_signature": False})
    old = int(time.time()) - 3600
    # Correctly signed by the AS, but an hour old.
    expired = jwt.encode(claims | {"iat": old, "nbf": old, "exp": old + 300}, as_key,
                         algorithm="EdDSA", headers=jwt.get_unverified_header(real_token))
    url = events_url(settings)
    r = run(raw_get(net, url, {"Authorization": f"DPoP {expired}",
                               "DPoP": assistant.dpop_proof("GET", url, expired)}))
    assert r.status_code == 401
    assert "expired" in r.json()["detail"]["error_description"]


def test_token_signed_by_someone_else_is_rejected(env):
    """An agent can't mint its own tokens: only the AS key is trusted."""
    settings, net, assistant = env
    own_key = load_private_key(private_key_path(settings.keys_dir, ASSISTANT))
    real_token = run(assistant.get_token(CALENDAR_AGENT, ["calendar:read"]))
    claims = jwt.decode(real_token, options={"verify_signature": False})
    forged = jwt.encode(claims | {"scope": "calendar:read calendar:write"}, own_key,
                        algorithm="EdDSA", headers=jwt.get_unverified_header(real_token))
    url = events_url(settings)
    r = run(raw_get(net, url, {"Authorization": f"DPoP {forged}",
                               "DPoP": assistant.dpop_proof("GET", url, forged)}))
    assert r.status_code == 401
