"""Shared settings for every service.

Each service is identified by an *agent id* (e.g. ``calendar-agent``).  That id
is used three ways:
  * as the ``sub``/``client_id`` when the agent asks for tokens,
  * as the ``aud`` (audience) of tokens meant for that agent,
  * as the key into ``service_urls`` to find where it lives.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

AUTH_SERVER = "auth-server"
ASSISTANT = "assistant"
CALENDAR_AGENT = "calendar-agent"
EMAIL_AGENT = "email-agent"

ALL_SERVICES = [AUTH_SERVER, ASSISTANT, CALENDAR_AGENT, EMAIL_AGENT]

DEFAULT_SERVICE_URLS = {
    AUTH_SERVER: "http://127.0.0.1:8000",
    ASSISTANT: "http://127.0.0.1:8001",
    CALENDAR_AGENT: "http://127.0.0.1:8002",
    EMAIL_AGENT: "http://127.0.0.1:8003",
}


@dataclass
class Settings:
    service_urls: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SERVICE_URLS))
    keys_dir: Path = PROJECT_ROOT / "keys"
    policy_path: Path = PROJECT_ROOT / "config" / "policy.json"
    # Short-lived tokens limit the damage if one leaks.
    access_token_ttl: int = 300
    # Client assertions and DPoP proofs are one-shot; they only need to live
    # long enough to cross the network.
    max_proof_age: int = 60
    # Tolerance for clocks that disagree slightly between machines.
    clock_skew: int = 30

    @property
    def issuer(self) -> str:
        return self.service_urls[AUTH_SERVER]

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/token"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"

    def url_for(self, agent_id: str) -> str:
        return self.service_urls[agent_id]

    def load_policy(self) -> dict:
        return json.loads(self.policy_path.read_text())

    @classmethod
    def from_env(cls) -> "Settings":
        """Override defaults with A2A_* environment variables."""
        s = cls()
        if keys_dir := os.environ.get("A2A_KEYS_DIR"):
            s.keys_dir = Path(keys_dir)
        if policy := os.environ.get("A2A_POLICY"):
            s.policy_path = Path(policy)
        if urls := os.environ.get("A2A_SERVICE_URLS"):
            s.service_urls.update(json.loads(urls))
        return s
