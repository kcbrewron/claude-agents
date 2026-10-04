"""The authorization server (AS): the one place that decides who may talk to whom.

Flow for one token request (OAuth 2.0 client credentials + private_key_jwt):

  1. The calling agent signs a short "client assertion" JWT with its private key
     (RFC 7523).  No shared secret ever crosses the network.
  2. The AS verifies that signature against the agent's *registered* public key,
     so it knows which agent is asking.
  3. The AS checks policy.json: may this agent get these scopes for that
     target (the ``resource``, RFC 8707)?
  4. The AS issues a short-lived access token JWT signed with *its own* key,
     with ``aud`` set to the one target agent and ``cnf.jkt`` binding the token
     to the caller's key (so a stolen token is useless without that key).
"""

from __future__ import annotations

import json
import time
import uuid

import jwt
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse

from .config import AUTH_SERVER, Settings
from .keys import (
    jwk_thumbprint,
    load_private_key,
    private_key_path,
    public_jwk,
    public_jwk_path,
    public_key_from_jwk,
)
from .replay import ReplayCache

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class OAuthError(HTTPException):
    """Errors in the RFC 6749 section 5.2 JSON shape."""

    def __init__(self, status: int, error: str, description: str):
        super().__init__(status, {"error": error, "error_description": description})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    signing_key = load_private_key(private_key_path(settings.keys_dir, AUTH_SERVER))
    signing_jwk = public_jwk(signing_key)
    policy = settings.load_policy()["agents"]

    # Registry of agent public keys. Loaded once; a real AS would use a database
    # and an admin API for registering/rotating keys.
    registry: dict[str, dict] = {}
    for agent_id in policy:
        registry[agent_id] = json.loads(public_jwk_path(settings.keys_dir, agent_id).read_text())

    assertion_replays = ReplayCache()
    app = FastAPI(title="Agent Authorization Server")

    @app.exception_handler(OAuthError)
    async def oauth_error_handler(_request, exc: OAuthError):
        headers = {"Cache-Control": "no-store"}
        return JSONResponse(exc.detail, status_code=exc.status_code, headers=headers)

    @app.get("/.well-known/oauth-authorization-server")
    def metadata():
        # RFC 8414 discovery document: lets clients find endpoints & keys.
        return {
            "issuer": settings.issuer,
            "token_endpoint": settings.token_endpoint,
            "jwks_uri": settings.jwks_uri,
            "grant_types_supported": ["client_credentials"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["EdDSA"],
            "dpop_signing_alg_values_supported": ["EdDSA"],
        }

    @app.get("/.well-known/jwks.json")
    def jwks():
        # Resource servers fetch this to verify the tokens we sign.
        return {"keys": [signing_jwk]}

    def authenticate_client(assertion: str, client_id: str | None) -> str:
        try:
            claimed = jwt.decode(assertion, options={"verify_signature": False})
        except jwt.PyJWTError as e:
            raise OAuthError(401, "invalid_client", f"malformed client assertion: {e}")

        agent_id = claimed.get("iss")
        if agent_id not in registry:
            raise OAuthError(401, "invalid_client", "unknown client")
        if client_id is not None and client_id != agent_id:
            raise OAuthError(401, "invalid_client", "client_id does not match assertion")

        try:
            claims = jwt.decode(
                assertion,
                public_key_from_jwk(registry[agent_id]),
                algorithms=["EdDSA"],  # never let the token choose its own algorithm
                # Audience is the AS *issuer identifier*, so an assertion made for
                # some other server can't be replayed here.
                audience=settings.issuer,
                leeway=settings.clock_skew,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "jti"]},
            )
        except jwt.PyJWTError as e:
            raise OAuthError(401, "invalid_client", f"client assertion rejected: {e}")

        if claims["sub"] != agent_id:
            raise OAuthError(401, "invalid_client", "assertion iss and sub must both be the client")
        if claims["exp"] - claims["iat"] > settings.max_proof_age:
            raise OAuthError(401, "invalid_client", "client assertion lifetime too long")
        if not assertion_replays.check_and_store(claims["jti"], claims["exp"] + settings.clock_skew):
            raise OAuthError(401, "invalid_client", "client assertion already used")
        return agent_id

    @app.post("/token")
    def token(
        grant_type: str = Form(...),
        client_assertion_type: str = Form(...),
        client_assertion: str = Form(...),
        resource: str = Form(...),
        scope: str = Form(""),
        client_id: str | None = Form(None),
    ):
        if grant_type != "client_credentials":
            raise OAuthError(400, "unsupported_grant_type", "only client_credentials is supported")
        if client_assertion_type != CLIENT_ASSERTION_TYPE:
            raise OAuthError(401, "invalid_client", "only private_key_jwt client auth is supported")

        agent_id = authenticate_client(client_assertion, client_id)

        # --- Authorization: least privilege, deny by default -----------------
        allowed = set(policy[agent_id]["grants"].get(resource, []))
        if not allowed:
            raise OAuthError(400, "invalid_target", f"{agent_id} may not call {resource}")
        requested = set(scope.split())
        if not requested:
            raise OAuthError(400, "invalid_scope", "request at least one scope")
        denied = requested - allowed
        if denied:
            raise OAuthError(400, "invalid_scope", f"not permitted: {' '.join(sorted(denied))}")

        now = int(time.time())
        claims = {
            "iss": settings.issuer,
            "sub": agent_id,
            "client_id": agent_id,
            "aud": resource,  # valid at exactly one agent
            "scope": " ".join(sorted(requested)),
            "iat": now,
            "nbf": now,
            "exp": now + settings.access_token_ttl,
            "jti": str(uuid.uuid4()),
            # Sender-constraint (RFC 9449): only the holder of the key with this
            # thumbprint can use the token.
            "cnf": {"jkt": jwk_thumbprint(registry[agent_id])},
        }
        access_token = jwt.encode(
            claims,
            signing_key,
            algorithm="EdDSA",
            headers={"kid": signing_jwk["kid"], "typ": "at+jwt"},  # RFC 9068
        )
        body = {
            "access_token": access_token,
            "token_type": "DPoP",
            "expires_in": settings.access_token_ttl,
            "scope": claims["scope"],
        }
        return JSONResponse(body, headers={"Cache-Control": "no-store"})

    return app
