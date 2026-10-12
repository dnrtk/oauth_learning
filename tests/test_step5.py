"""演習 5: トークンエンドポイント (認可サーバー)。"""

from __future__ import annotations

import time
from typing import Any

import pytest

from oauth_sample import config
from oauth_sample.common import OAuthError, Request, encode_basic_auth
from oauth_sample.config import Settings

from .conftest import Impl


def _token_request(authorization: str | None) -> Request:
    headers = {"authorization": authorization} if authorization is not None else {}
    return Request(method="POST", path="/token", query={}, form={}, headers=headers, cookies={})


def _server_with_code(impl: Impl, settings: Settings, code_challenge: str | None = None) -> tuple[Any, str]:
    server = impl.auth_server.AuthorizationServer(settings)
    code = "test-code-0123456789abcdefghijklmnopqrstuv"
    server.codes[code] = impl.auth_server.AuthorizationCodeRecord(
        code=code,
        client_id=config.CLIENT_ID,
        redirect_uri=settings.redirect_uri,
        username="alice",
        scope="profile",
        expires_at=time.time() + 60,
        code_challenge=code_challenge,
    )
    return server, code


def _client(settings: Settings) -> config.ClientRegistration:
    return config.registered_clients(settings)[config.CLIENT_ID]


# --- 5-1 クライアント認証 -------------------------------------------------
def test_step5_1_authenticate_client_ok(impl: Impl, settings: Settings) -> None:
    server = impl.auth_server.AuthorizationServer(settings)
    request = _token_request(encode_basic_auth(config.CLIENT_ID, config.CLIENT_SECRET))
    assert server.authenticate_client(request).client_id == config.CLIENT_ID


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "Bearer something",
        encode_basic_auth(config.CLIENT_ID, "wrong-secret"),
        encode_basic_auth("unknown-client", config.CLIENT_SECRET),
    ],
)
def test_step5_1_authenticate_client_ng(impl: Impl, settings: Settings, authorization: str | None) -> None:
    server = impl.auth_server.AuthorizationServer(settings)
    with pytest.raises(OAuthError) as info:
        server.authenticate_client(_token_request(authorization))
    assert info.value.error == "invalid_client"
    assert info.value.status == 401


# --- 5-2 認可コードの検証 --------------------------------------------------
def test_step5_2_redeem_ok_and_single_use(impl: Impl, settings: Settings) -> None:
    server, code = _server_with_code(impl, settings)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": settings.redirect_uri}
    record = server.redeem_authorization_code(form, _client(settings))
    assert record.username == "alice"
    assert server.codes[code].used is True

    with pytest.raises(OAuthError) as info:
        server.redeem_authorization_code(form, _client(settings))
    assert info.value.error == "invalid_grant", "2 回目の使用は拒否されなければなりません"


def test_step5_2_reuse_revokes_tokens(impl: Impl, settings: Settings) -> None:
    server, code = _server_with_code(impl, settings)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": settings.redirect_uri}
    server.redeem_authorization_code(form, _client(settings))
    tokens = server.issue_tokens("alice", config.CLIENT_ID, "profile", grant_id=code)
    with pytest.raises(OAuthError):
        server.redeem_authorization_code(form, _client(settings))
    assert server.access_tokens[tokens["access_token"]].revoked is True, (
        "認可コードが再利用されたら、そのコードから発行したトークンを失効させます"
    )


def test_step5_2_missing_code(impl: Impl, settings: Settings) -> None:
    server, _ = _server_with_code(impl, settings)
    with pytest.raises(OAuthError) as info:
        server.redeem_authorization_code({"redirect_uri": settings.redirect_uri}, _client(settings))
    assert info.value.error == "invalid_request"


@pytest.mark.parametrize("case", ["unknown_code", "expired", "other_client", "wrong_redirect_uri"])
def test_step5_2_invalid_grant(impl: Impl, settings: Settings, case: str) -> None:
    server, code = _server_with_code(impl, settings)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": settings.redirect_uri}
    client = _client(settings)
    if case == "unknown_code":
        form["code"] = "no-such-code"
    elif case == "expired":
        server.codes[code].expires_at = time.time() - 1
    elif case == "other_client":
        client = config.ClientRegistration("other", "secret", "Other", (settings.redirect_uri,), frozenset())
    elif case == "wrong_redirect_uri":
        form["redirect_uri"] = "http://127.0.0.1:8000/other"
    with pytest.raises(OAuthError) as info:
        server.redeem_authorization_code(form, client)
    assert info.value.error == "invalid_grant"
    if case != "unknown_code":
        assert server.codes[code].used is False, "検証に失敗したときは使用済みにしません"


# --- 5-3 トークン発行 -------------------------------------------------------
def test_step5_3_issue_tokens(impl: Impl, settings: Settings) -> None:
    server = impl.auth_server.AuthorizationServer(settings)
    body = server.issue_tokens("alice", config.CLIENT_ID, "profile notes:read", grant_id="g1")
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == config.ACCESS_TOKEN_TTL_SECONDS
    assert body["scope"] == "profile notes:read"
    assert len(body["access_token"]) >= 32 and len(body["refresh_token"]) >= 32
    assert body["access_token"] != body["refresh_token"]

    access = server.access_tokens[body["access_token"]]
    assert (access.username, access.client_id, access.scope, access.grant_id) == (
        "alice",
        config.CLIENT_ID,
        "profile notes:read",
        "g1",
    )
    refresh = server.refresh_tokens[body["refresh_token"]]
    assert (refresh.username, refresh.grant_id) == ("alice", "g1")
    assert access.expires_at < refresh.expires_at
