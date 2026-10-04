"""What an agent does when it wants to call another agent.

  token = get_token(audience="calendar-agent", scopes=["calendar:read"])
      -> signs a client assertion with our private key, POSTs it to /token
  request("GET", "calendar-agent", "/events")
      -> sends  Authorization: DPoP <token>
                DPoP: <fresh proof JWT signed with our private key>

The DPoP proof is new for every request and names the exact method + URL, so
a captured request can't be replayed or redirected to another endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid

import httpx
import jwt

from .config import Settings
from .keys import load_private_key, private_key_path, public_jwk
from .auth_server import CLIENT_ASSERTION_TYPE


def access_token_hash(access_token: str) -> str:
    """The DPoP ``ath`` claim: ties a proof to one specific access token."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class TokenRequestError(Exception):
    def __init__(self, status: int, body: dict):
        super().__init__(f"{status}: {body.get('error')}: {body.get('error_description')}")
        self.status = status
        self.body = body


class AgentClient:
    # Refresh a little before expiry so a token never dies mid-flight.
    REFRESH_MARGIN = 30

    def __init__(
        self,
        agent_id: str,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.agent_id = agent_id
        self.settings = settings
        self._key = load_private_key(private_key_path(settings.keys_dir, agent_id))
        self._jwk = public_jwk(self._key)
        self._http = httpx.AsyncClient(transport=transport, timeout=10)
        self._tokens: dict[tuple[str, frozenset[str]], tuple[str, float]] = {}

    # -- step 1: prove who we are to the authorization server ----------------
    def client_assertion(self) -> str:
        now = int(time.time())
        claims = {
            "iss": self.agent_id,
            "sub": self.agent_id,
            "aud": self.settings.issuer,
            "iat": now,
            "exp": now + 60,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(claims, self._key, algorithm="EdDSA", headers={"kid": self._jwk["kid"]})

    async def get_token(self, audience: str, scopes: list[str]) -> str:
        cache_key = (audience, frozenset(scopes))
        cached = self._tokens.get(cache_key)
        if cached and cached[1] - self.REFRESH_MARGIN > time.time():
            return cached[0]

        resp = await self._http.post(
            self.settings.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self.agent_id,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": self.client_assertion(),
                "resource": audience,
                "scope": " ".join(scopes),
            },
        )
        body = resp.json()
        if resp.status_code != 200:
            raise TokenRequestError(resp.status_code, body)
        self._tokens[cache_key] = (body["access_token"], time.time() + body["expires_in"])
        return body["access_token"]

    # -- step 2: prove we hold the key the token is bound to -----------------
    def dpop_proof(self, method: str, url: str, access_token: str) -> str:
        public = {k: self._jwk[k] for k in ("kty", "crv", "x")}
        claims = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": url.split("?", 1)[0].split("#", 1)[0],
            "iat": int(time.time()),
            "ath": access_token_hash(access_token),
        }
        return jwt.encode(
            claims, self._key, algorithm="EdDSA", headers={"typ": "dpop+jwt", "jwk": public}
        )

    async def request(
        self, method: str, audience: str, path: str, scopes: list[str], **kwargs
    ) -> httpx.Response:
        token = await self.get_token(audience, scopes)
        url = self.settings.url_for(audience) + path
        headers = kwargs.pop("headers", {}) | {
            "Authorization": f"DPoP {token}",
            "DPoP": self.dpop_proof(method, url, token),
        }
        return await self._http.request(method, url, headers=headers, **kwargs)

    async def aclose(self) -> None:
        await self._http.aclose()
