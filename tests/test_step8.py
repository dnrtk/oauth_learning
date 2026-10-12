"""演習 8: リフレッシュトークン (認可サーバー・クライアント)。"""

from __future__ import annotations

import time

import pytest

from oauth_sample import config
from oauth_sample.common import JsonDict, OAuthError
from oauth_sample.config import Settings

from .conftest import Impl


def _client(settings: Settings) -> config.ClientRegistration:
    return config.registered_clients(settings)[config.CLIENT_ID]


def test_step8_1_refresh_rotates_token(impl: Impl, settings: Settings) -> None:
    server = impl.auth_server.AuthorizationServer(settings)
    first = server.issue_tokens("alice", config.CLIENT_ID, "profile", grant_id="g")
    second = server.exchange_refresh_token({"refresh_token": first["refresh_token"]}, _client(settings))

    assert second["access_token"] != first["access_token"]
    assert second["refresh_token"] != first["refresh_token"], "リフレッシュトークンもローテーションします"
    assert second["scope"] == "profile"
    assert server.refresh_tokens[first["refresh_token"]].revoked is True
    assert server.access_tokens[second["access_token"]].grant_id == "g"


def test_step8_1_reuse_of_rotated_token_revokes_grant(impl: Impl, settings: Settings) -> None:
    server = impl.auth_server.AuthorizationServer(settings)
    first = server.issue_tokens("alice", config.CLIENT_ID, "profile", grant_id="g")
    second = server.exchange_refresh_token({"refresh_token": first["refresh_token"]}, _client(settings))

    with pytest.raises(OAuthError) as info:
        server.exchange_refresh_token({"refresh_token": first["refresh_token"]}, _client(settings))
    assert info.value.error == "invalid_grant"
    assert server.access_tokens[second["access_token"]].revoked is True, (
        "使用済みのリフレッシュトークンが再び使われたら、その許可から発行したトークンをすべて失効させます"
    )
    assert server.refresh_tokens[second["refresh_token"]].revoked is True


@pytest.mark.parametrize("case", ["missing", "unknown", "expired", "other_client"])
def test_step8_1_refresh_errors(impl: Impl, settings: Settings, case: str) -> None:
    server = impl.auth_server.AuthorizationServer(settings)
    body = server.issue_tokens("alice", config.CLIENT_ID, "profile", grant_id="g")
    form = {"refresh_token": body["refresh_token"]}
    client = _client(settings)
    if case == "missing":
        form = {}
    elif case == "unknown":
        form["refresh_token"] = "no-such-token"
    elif case == "expired":
        server.refresh_tokens[body["refresh_token"]].expires_at = time.time() - 1
    elif case == "other_client":
        client = config.ClientRegistration("other", "secret", "Other", (), frozenset())
    with pytest.raises(OAuthError) as info:
        server.exchange_refresh_token(form, client)
    assert info.value.error == ("invalid_request" if case == "missing" else "invalid_grant")


def test_step8_2_refresh_access_token(impl: Impl, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, str]] = []

    def fake_post(_settings: Settings, form: dict[str, str]) -> JsonDict:
        sent.append(dict(form))
        return {"access_token": "new"}

    monkeypatch.setattr(impl.client, "post_to_token_endpoint", fake_post)
    assert impl.client.refresh_access_token(settings, "rt") == {"access_token": "new"}
    assert sent == [{"grant_type": "refresh_token", "refresh_token": "rt"}]
