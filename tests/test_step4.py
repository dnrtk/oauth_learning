"""演習 4: state を検証し、認可コードをトークンと交換する (クライアント)。"""

from __future__ import annotations

import pytest

from oauth_sample.common import JsonDict
from oauth_sample.config import Settings

from .conftest import Impl


@pytest.mark.parametrize(
    ("expected", "received", "ok"),
    [
        ("abc", "abc", True),
        ("abc", "abd", False),
        ("abc", None, False),
        (None, "abc", False),
        (None, None, False),
    ],
)
def test_step4_1_verify_state(impl: Impl, expected: str | None, received: str | None, ok: bool) -> None:
    assert impl.client.verify_state(expected, received) is ok


def test_step4_2_exchange_code(impl: Impl, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, str]] = []

    def fake_post(_settings: Settings, form: dict[str, str]) -> JsonDict:
        sent.append(dict(form))
        return {"access_token": "at", "token_type": "Bearer"}

    monkeypatch.setattr(impl.client, "post_to_token_endpoint", fake_post)
    result = impl.client.exchange_code_for_token(settings, "the-code", None)
    assert result == {"access_token": "at", "token_type": "Bearer"}
    assert sent == [
        {"grant_type": "authorization_code", "code": "the-code", "redirect_uri": settings.redirect_uri}
    ]

    sent.clear()
    impl.client.exchange_code_for_token(settings, "the-code", "verifier")
    assert sent[0]["code_verifier"] == "verifier"
