"""Run all agents inside one Python process, routed by hostname.

Real HTTP requests and responses still flow between the agents (headers,
status codes, JSON bodies), just without opening sockets.  Used by the demo
and the tests.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from .agents import assistant, calendar_agent, email_agent
from .auth_server import create_app as create_auth_server
from .config import ALL_SERVICES, ASSISTANT, AUTH_SERVER, CALENDAR_AGENT, EMAIL_AGENT, Settings
from .keys import bootstrap_keys


class HostRouterTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self._routes: dict[str, httpx.ASGITransport] = {}

    def mount(self, base_url: str, app) -> None:
        self._routes[httpx.URL(base_url).host] = httpx.ASGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        route = self._routes.get(request.url.host)
        if route is None:
            raise httpx.ConnectError(f"no service at {request.url.host}", request=request)
        return await route.handle_async_request(request)


def build_network(keys_dir: Path) -> tuple[Settings, HostRouterTransport, dict]:
    settings = Settings(
        service_urls={name: f"http://{name}.local" for name in ALL_SERVICES},
        keys_dir=keys_dir,
    )
    bootstrap_keys(keys_dir, ALL_SERVICES)
    net = HostRouterTransport()
    apps = {
        AUTH_SERVER: create_auth_server(settings),
        ASSISTANT: assistant.create_app(settings, net),
        CALENDAR_AGENT: calendar_agent.create_app(settings, net),
        EMAIL_AGENT: email_agent.create_app(settings, net),
    }
    for name, app in apps.items():
        net.mount(settings.url_for(name), app)
    return settings, net, apps
