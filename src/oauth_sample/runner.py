"""3 つのサーバー (クライアント・認可サーバー・リソースサーバー) をまとめて起動する。"""

from __future__ import annotations

import importlib
from http.server import ThreadingHTTPServer
from typing import Literal

from .common import start_server
from .config import Settings

type Implementation = Literal["exercise", "solution"]


def start_all(implementation: Implementation, settings: Settings) -> list[ThreadingHTTPServer]:
    """指定した実装 (演習版 or 解答版) で 3 つのサーバーを起動し、サーバーのリストを返す。"""
    package = f"{__package__}.{implementation}"
    auth_server = importlib.import_module(f"{package}.auth_server")
    resource_server = importlib.import_module(f"{package}.resource_server")
    client = importlib.import_module(f"{package}.client")

    return [
        start_server(
            "auth", settings.host, settings.auth_port, auth_server.AuthorizationServer(settings).handle
        ),
        start_server(
            "resource",
            settings.host,
            settings.resource_port,
            resource_server.ResourceServer(settings).handle,
        ),
        start_server("client", settings.host, settings.client_port, client.ClientApp(settings).handle),
    ]


def stop_all(servers: list[ThreadingHTTPServer]) -> None:
    for server in servers:
        server.shutdown()
        server.server_close()
