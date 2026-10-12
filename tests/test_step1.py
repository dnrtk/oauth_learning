"""演習 1: 認可リクエストの URL を組み立てる (クライアント)。"""

from __future__ import annotations

import urllib.parse

from oauth_sample import config
from oauth_sample.config import Settings

from .conftest import Impl


def _parse(url: str) -> tuple[str, dict[str, str]]:
    split = urllib.parse.urlsplit(url)
    base = f"{split.scheme}://{split.netloc}{split.path}"
    return base, dict(urllib.parse.parse_qsl(split.query))


def test_step1_1_basic_parameters(impl: Impl, settings: Settings) -> None:
    url = impl.client.build_authorization_url(settings, "xyz-state", None)
    base, params = _parse(url)
    assert base == settings.authorization_endpoint, "行き先は認可エンドポイントです"
    assert params == {
        "response_type": "code",
        "client_id": config.CLIENT_ID,
        "redirect_uri": settings.redirect_uri,
        "scope": config.CLIENT_SCOPE,
        "state": "xyz-state",
    }


def test_step1_1_values_are_url_encoded(impl: Impl, settings: Settings) -> None:
    url = impl.client.build_authorization_url(settings, "a b&c", None)
    assert " " not in url, "空白などはエンコードが必要です (urllib.parse.urlencode を使いましょう)"
    _, params = _parse(url)
    assert params["state"] == "a b&c"
    assert params["redirect_uri"] == settings.redirect_uri


def test_step1_1_with_code_challenge(impl: Impl, settings: Settings) -> None:
    url = impl.client.build_authorization_url(settings, "s", "challenge-value")
    _, params = _parse(url)
    assert params["code_challenge"] == "challenge-value"
    assert params["code_challenge_method"] == "S256"
