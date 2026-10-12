"""演習 2: 認可リクエストを検証する (認可サーバー)。"""

from __future__ import annotations

from typing import Any

import pytest

from oauth_sample import config
from oauth_sample.common import OAuthError
from oauth_sample.config import Settings

from .conftest import Impl


def _query(settings: Settings, **overrides: str | None) -> dict[str, str]:
    query: dict[str, str | None] = {
        "response_type": "code",
        "client_id": config.CLIENT_ID,
        "redirect_uri": settings.redirect_uri,
        "scope": "profile notes:read",
        "state": "s1",
    }
    query.update(overrides)
    return {k: v for k, v in query.items() if v is not None}


def _validate(impl: Impl, settings: Settings, query: dict[str, str]) -> Any:
    clients = config.registered_clients(settings)
    return impl.auth_server.validate_authorization_request(query, clients)


def test_step2_1_valid_request(impl: Impl, settings: Settings) -> None:
    result = _validate(impl, settings, _query(settings))
    assert result == impl.auth_server.AuthorizationRequest(
        client_id=config.CLIENT_ID,
        redirect_uri=settings.redirect_uri,
        scope="profile notes:read",
        state="s1",
    )


def test_step2_1_state_is_optional(impl: Impl, settings: Settings) -> None:
    result = _validate(impl, settings, _query(settings, state=None))
    assert result.state is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"client_id": "unknown-client"},
        {"client_id": None},
        {"redirect_uri": "https://attacker.example/callback"},
        {"redirect_uri": None},
        # 前方一致やパスの細工を許してはいけない (完全一致が必要)
        {"redirect_uri": "http://127.0.0.1:8000/callback/../evil"},
        {"redirect_uri": "http://127.0.0.1:8000/callback?next=https://attacker.example/"},
    ],
)
def test_step2_1_untrusted_redirect(
    impl: Impl, settings: Settings, overrides: dict[str, str | None]
) -> None:
    with pytest.raises(impl.auth_server.UntrustedRedirectError):
        _validate(impl, settings, _query(settings, **overrides))


def test_step2_1_client_checked_before_response_type(impl: Impl, settings: Settings) -> None:
    """client_id / redirect_uri が不正なら、他のエラーより先に UntrustedRedirectError になること。"""
    query = _query(settings, redirect_uri="https://attacker.example/", response_type="token")
    with pytest.raises(impl.auth_server.UntrustedRedirectError):
        _validate(impl, settings, query)


def test_step2_1_unsupported_response_type(impl: Impl, settings: Settings) -> None:
    with pytest.raises(OAuthError) as info:
        _validate(impl, settings, _query(settings, response_type="token"))
    assert info.value.error == "unsupported_response_type"


@pytest.mark.parametrize("scope", ["admin", "profile admin", "", None])
def test_step2_1_invalid_scope(impl: Impl, settings: Settings, scope: str | None) -> None:
    with pytest.raises(OAuthError) as info:
        _validate(impl, settings, _query(settings, scope=scope))
    assert info.value.error == "invalid_scope"
