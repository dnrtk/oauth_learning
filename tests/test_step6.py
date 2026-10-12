"""演習 6: アクセストークンで API を守る (認可サーバー・リソースサーバー・クライアント)。"""

from __future__ import annotations

import time

import pytest

from oauth_sample import config
from oauth_sample.common import HttpResult, JsonDict
from oauth_sample.config import Settings

from .conftest import Impl


# --- 6-1 イントロスペクション (認可サーバー) ------------------------------
def test_step6_1_introspect_active(impl: Impl, settings: Settings) -> None:
    server = impl.auth_server.AuthorizationServer(settings)
    body = server.issue_tokens("alice", config.CLIENT_ID, "profile", grant_id="g")
    info = server.introspect(body["access_token"])
    assert info["active"] is True
    assert info["username"] == "alice"
    assert info["client_id"] == config.CLIENT_ID
    assert info["scope"] == "profile"
    assert isinstance(info["exp"], int)


@pytest.mark.parametrize("case", ["unknown", "expired", "revoked", "refresh_token"])
def test_step6_1_introspect_inactive(impl: Impl, settings: Settings, case: str) -> None:
    server = impl.auth_server.AuthorizationServer(settings)
    body = server.issue_tokens("alice", config.CLIENT_ID, "profile", grant_id="g")
    token = body["access_token"]
    if case == "unknown":
        token = "no-such-token"
    elif case == "expired":
        server.access_tokens[token].expires_at = time.time() - 1
    elif case == "revoked":
        server.access_tokens[token].revoked = True
    elif case == "refresh_token":
        token = body["refresh_token"]  # リフレッシュトークンで API は呼べない
    assert server.introspect(token) == {"active": False}


# --- 6-2 Bearer トークンの取り出し (リソースサーバー) ---------------------
@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer abc123", "abc123"),
        ("bearer abc123", "abc123"),
        (None, None),
        ("", None),
        ("Bearer", None),
        ("Bearer ", None),
        ("Basic abc123", None),
    ],
)
def test_step6_2_extract_bearer_token(impl: Impl, header: str | None, expected: str | None) -> None:
    assert impl.resource_server.extract_bearer_token(header) == expected


# --- 6-3 認可サーバーへの問い合わせ (リソースサーバー) -------------------
def test_step6_3_introspect_token(impl: Impl, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, dict[str, str] | None, dict[str, str] | None]] = []

    def fake_http_request(
        app: str,
        method: str,
        url: str,
        *,
        form: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        calls.append((method, url, form, headers))
        return HttpResult(status=200, body={"active": True, "scope": "profile"}, headers={})

    monkeypatch.setattr(impl.resource_server, "http_request", fake_http_request)
    assert impl.resource_server.introspect_token(settings, "tok") == {"active": True, "scope": "profile"}
    method, url, form, headers = calls[0]
    assert (method, url, form) == ("POST", settings.introspection_endpoint, {"token": "tok"})
    assert headers is not None
    assert headers["Authorization"].startswith("Basic "), "リソースサーバー自身の認証情報が必要です"


# --- 6-4 スコープの確認 (リソースサーバー) --------------------------------
@pytest.mark.parametrize(
    ("scope", "required", "ok"),
    [
        ("profile notes:read", "profile", True),
        ("profile notes:read", "notes:read", True),
        ("profile", "notes:read", False),
        ("notes:read", "notes", False),  # 部分一致ではダメ
        (None, "profile", False),
    ],
)
def test_step6_4_has_scope(impl: Impl, scope: str | None, required: str, ok: bool) -> None:
    info: JsonDict = {"active": True}
    if scope is not None:
        info["scope"] = scope
    assert impl.resource_server.has_scope(info, required) is ok


# --- 6-5 API 呼び出し (クライアント) --------------------------------------
def test_step6_5_call_resource_api(impl: Impl, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, dict[str, str] | None]] = []

    def fake_http_request(
        app: str,
        method: str,
        url: str,
        *,
        form: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        calls.append((method, url, headers))
        return HttpResult(status=200, body={"ok": True}, headers={})

    monkeypatch.setattr(impl.client, "http_request", fake_http_request)
    result = impl.client.call_resource_api(settings, "/api/profile", "tok")
    assert result.body == {"ok": True}
    assert calls == [
        ("GET", settings.resource_base_url + "/api/profile", {"Authorization": "Bearer tok"})
    ]
