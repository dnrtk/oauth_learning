"""演習 3: 認可コードを発行して返す (認可サーバー)。"""

from __future__ import annotations

import time
import urllib.parse

from oauth_sample import config
from oauth_sample.config import Settings

from .conftest import Impl


def test_step3_1_issue_code(impl: Impl, settings: Settings) -> None:
    server = impl.auth_server.AuthorizationServer(settings)
    request = impl.auth_server.AuthorizationRequest(
        client_id=config.CLIENT_ID,
        redirect_uri=settings.redirect_uri,
        scope="profile",
        state="s",
        code_challenge="c" * 43,
    )
    code1 = server.issue_authorization_code(request, "alice")
    code2 = server.issue_authorization_code(request, "alice")
    assert isinstance(code1, str) and len(code1) >= 32, "推測できない十分な長さが必要です"
    assert code1 != code2, "毎回違う値でなければなりません"

    record = server.codes[code1]
    assert record.code == code1
    assert record.client_id == config.CLIENT_ID
    assert record.redirect_uri == settings.redirect_uri
    assert record.username == "alice"
    assert record.scope == "profile"
    assert record.code_challenge == "c" * 43
    assert record.used is False
    remaining = record.expires_at - time.time()
    assert 0 < remaining <= config.AUTHORIZATION_CODE_TTL_SECONDS


def test_step3_2_response_url(impl: Impl) -> None:
    url = impl.auth_server.build_authorization_response_url(
        "http://127.0.0.1:8000/callback", "the-code", "st ate"
    )
    split = urllib.parse.urlsplit(url)
    assert f"{split.scheme}://{split.netloc}{split.path}" == "http://127.0.0.1:8000/callback"
    assert dict(urllib.parse.parse_qsl(split.query)) == {"code": "the-code", "state": "st ate"}


def test_step3_2_response_url_without_state(impl: Impl) -> None:
    url = impl.auth_server.build_authorization_response_url("http://127.0.0.1:8000/callback", "c", None)
    assert dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)) == {"code": "c"}
