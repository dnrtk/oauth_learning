"""テスト共通の設定。

    uv run pytest                    # 演習版 (exercise) をテスト
    uv run pytest --impl solution    # 解答版 (solution) をテスト
    uv run pytest -k step1           # 演習 1 のテストだけ実行
"""

from __future__ import annotations

import importlib
import socket
from collections.abc import Iterator
from dataclasses import dataclass
from types import ModuleType

import pytest

from oauth_sample.config import Settings
from oauth_sample.runner import Implementation, start_all, stop_all


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--impl",
        choices=["exercise", "solution"],
        default="exercise",
        help="テスト対象の実装 (既定: exercise)",
    )


@dataclass(frozen=True)
class Impl:
    name: Implementation
    client: ModuleType
    auth_server: ModuleType
    resource_server: ModuleType
    pkce: ModuleType


@pytest.fixture(scope="session")
def impl(request: pytest.FixtureRequest) -> Impl:
    name: Implementation = request.config.getoption("--impl")
    package = f"oauth_sample.{name}"
    return Impl(
        name=name,
        client=importlib.import_module(f"{package}.client"),
        auth_server=importlib.import_module(f"{package}.auth_server"),
        resource_server=importlib.import_module(f"{package}.resource_server"),
        pkce=importlib.import_module(f"{package}.pkce"),
    )


@pytest.fixture
def settings() -> Settings:
    return Settings()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def _running(impl: Impl, use_pkce: bool) -> Iterator[Settings]:
    settings = Settings(
        client_port=_free_port(),
        auth_port=_free_port(),
        resource_port=_free_port(),
        use_pkce=use_pkce,
    )
    servers = start_all(impl.name, settings)
    try:
        yield settings
    finally:
        stop_all(servers)


@pytest.fixture
def running_without_pkce(impl: Impl) -> Iterator[Settings]:
    """空いているポートで 3 サーバーを起動する (PKCE 無効)。"""
    yield from _running(impl, use_pkce=False)


@pytest.fixture
def running_with_pkce(impl: Impl) -> Iterator[Settings]:
    """空いているポートで 3 サーバーを起動する (PKCE 有効)。"""
    yield from _running(impl, use_pkce=True)
