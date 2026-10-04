"""What an agent does when another agent calls it.

For every request we answer three questions, in order:

  1. Is the access token genuine?      signature from the AS, right issuer,
                                       addressed to *me* (aud), not expired
  2. Is the caller the token's owner?  DPoP proof signed by the key named in
                                       the token's cnf.jkt, for this exact
                                       method + URL, fresh, never seen before
  3. Is the caller allowed to do this? token carries the scope this endpoint
                                       requires

Usage in a FastAPI agent:

    verifier = AccessTokenVerifier("calendar-agent", settings)

    @app.get("/events")
    def list_events(caller: Caller = Depends(verifier.require("calendar:read"))):
        ...
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
import jwt
from fastapi import HTTPException, Request

from .client import access_token_hash
from .config import Settings
from .keys import jwk_thumbprint, public_key_from_jwk
from .replay import ReplayCache


@dataclass(frozen=True)
class Caller:
    agent_id: str
    scopes: frozenset[str]


def _unauthorized(description: str) -> HTTPException:
    return HTTPException(
        401,
        detail={"error": "invalid_token", "error_description": description},
        headers={"WWW-Authenticate": f'DPoP algs="EdDSA", error="invalid_token", error_description="{description}"'},
    )


class AccessTokenVerifier:
    # Don't let unknown-kid tokens make us hammer the AS's JWKS endpoint.
    JWKS_MIN_REFRESH_INTERVAL = 30

    def __init__(
        self,
        audience: str,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.audience = audience
        self.settings = settings
        self._http = httpx.AsyncClient(transport=transport, timeout=10)
        self._keys: dict[str, dict] = {}
        self._last_fetch = 0.0
        self._proof_replays = ReplayCache()

    async def _signing_key(self, kid: str | None):
        """Look up the AS public key by kid, refetching JWKS on a miss (key rotation)."""
        if kid not in self._keys and time.time() - self._last_fetch > self.JWKS_MIN_REFRESH_INTERVAL:
            resp = await self._http.get(self.settings.jwks_uri)
            resp.raise_for_status()
            self._keys = {k["kid"]: k for k in resp.json()["keys"]}
            self._last_fetch = time.time()
        if kid not in self._keys:
            raise _unauthorized("unknown signing key")
        return public_key_from_jwk(self._keys[kid])

    async def verify(self, request: Request) -> Caller:
        # ---- 1. the access token ---------------------------------------------
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "dpop" or not token:
            # Plain "Bearer" is refused: our tokens are only valid with a proof.
            raise _unauthorized("expected 'Authorization: DPoP <token>'")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("typ") != "at+jwt":
                raise _unauthorized("not an access token")
            claims = jwt.decode(
                token,
                await self._signing_key(header.get("kid")),
                algorithms=["EdDSA"],
                issuer=self.settings.issuer,
                audience=self.audience,  # a token minted for another agent is useless here
                leeway=self.settings.clock_skew,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "jti", "cnf"]},
            )
        except jwt.PyJWTError as e:
            raise _unauthorized(f"access token rejected: {e}")

        # ---- 2. the DPoP proof of possession -----------------------------------
        proof = request.headers.get("dpop")
        if not proof:
            raise _unauthorized("missing DPoP proof")
        try:
            proof_header = jwt.get_unverified_header(proof)
            if proof_header.get("typ") != "dpop+jwt" or proof_header.get("alg") != "EdDSA":
                raise _unauthorized("bad DPoP proof header")
            proof_jwk = proof_header.get("jwk") or {}
            # Is the key that signed this proof the one the token is bound to?
            if jwk_thumbprint(proof_jwk) != claims["cnf"].get("jkt"):
                raise _unauthorized("DPoP key does not match token binding")
            proof_claims = jwt.decode(
                proof,
                public_key_from_jwk(proof_jwk),
                algorithms=["EdDSA"],
                leeway=self.settings.clock_skew,
                options={"require": ["jti", "htm", "htu", "iat", "ath"]},
            )
        except (jwt.PyJWTError, KeyError, ValueError) as e:
            raise _unauthorized(f"DPoP proof rejected: {e}")

        # Build the URL from our *configured* public address, not the Host header,
        # so a proxy in front of us (or a spoofed Host) doesn't break or bypass this.
        expected_htu = self.settings.url_for(self.audience) + request.url.path
        if proof_claims["htm"] != request.method or proof_claims["htu"] != expected_htu:
            raise _unauthorized("DPoP proof is for a different request")
        if proof_claims["ath"] != access_token_hash(token):
            raise _unauthorized("DPoP proof is for a different access token")
        age = time.time() - proof_claims["iat"]
        if abs(age) > self.settings.max_proof_age:
            raise _unauthorized("DPoP proof is stale")
        expiry = proof_claims["iat"] + self.settings.max_proof_age + self.settings.clock_skew
        if not self._proof_replays.check_and_store(proof_claims["jti"], expiry):
            raise _unauthorized("DPoP proof replayed")

        return Caller(agent_id=claims["sub"], scopes=frozenset(claims.get("scope", "").split()))

    def require(self, *scopes: str):
        """FastAPI dependency: authenticate the caller and demand these scopes."""

        async def dependency(request: Request) -> Caller:
            caller = await self.verify(request)
            missing = set(scopes) - caller.scopes
            if missing:
                raise HTTPException(
                    403,
                    detail={"error": "insufficient_scope", "error_description": f"needs {' '.join(sorted(missing))}"},
                    headers={"WWW-Authenticate": f'DPoP error="insufficient_scope", scope="{" ".join(scopes)}"'},
                )
            return caller

        return dependency
