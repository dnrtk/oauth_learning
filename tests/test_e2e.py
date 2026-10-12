"""通しテスト: ブラウザの動きを再現して、3 つのサーバーを実際に HTTP でつないで確かめる。

    演習 1〜6 が終わったら  … test_e2e_flow_without_pkce が通るはず
    演習 7 が終わったら     … test_e2e_flow_with_pkce が通るはず
    演習 8 が終わったら     … test_e2e_refresh が通るはず
"""

from __future__ import annotations

import http.cookiejar
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from oauth_sample import config
from oauth_sample.common import encode_basic_auth
from oauth_sample.config import Settings


@dataclass
class Page:
    status: int
    url: str
    location: str | None
    text: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


class Browser:
    """Cookie を覚えるが、リダイレクトは自動では追わない簡易ブラウザ。"""

    def __init__(self) -> None:
        self.cookies = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies),
            _NoRedirect(),
        )

    def request(self, url: str, form: dict[str, str] | None = None) -> Page:
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        try:
            with self._opener.open(url, data=data, timeout=10) as resp:
                return Page(resp.status, url, resp.headers.get("Location"), resp.read().decode())
        except urllib.error.HTTPError as err:
            return Page(err.code, url, err.headers.get("Location"), err.read().decode())

    def follow(self, page: Page) -> Page:
        assert page.status == 302, f"リダイレクトを期待しましたが {page.status} でした:\n{page.text[:500]}"
        assert page.location is not None
        return self.request(urllib.parse.urljoin(page.url, page.location))


def _authorize_until_callback(browser: Browser, settings: Settings) -> Page:
    """「連携する」→ ログイン → 同意 まで進め、クライアントのコールバックへのリダイレクトを返す。"""
    page = browser.request(settings.client_base_url + "/login")
    assert page.location is not None and page.location.startswith(settings.authorization_endpoint)

    page = browser.follow(page)  # 認可サーバー /authorize → 未ログインなので /login へ
    page = browser.follow(page)  # ログイン画面
    assert page.status == 200
    next_url = re.search(r'name="next" value="([^"]+)"', page.text)
    assert next_url is not None
    page = browser.request(
        settings.auth_base_url + "/login",
        {"username": "alice", "password": config.USERS["alice"], "next": next_url.group(1).replace("&amp;", "&")},
    )
    page = browser.follow(page)  # /authorize に戻ると同意画面
    assert page.status == 200, page.text[:500]
    request_id = re.search(r'name="request_id" value="([^"]+)"', page.text)
    assert request_id is not None
    page = browser.request(
        settings.auth_base_url + "/authorize/decision",
        {"request_id": request_id.group(1), "decision": "approve"},
    )
    assert page.location is not None and page.location.startswith(settings.redirect_uri)
    return page


def _get_profile(browser: Browser, settings: Settings) -> Page:
    return browser.request(settings.client_base_url + "/api/profile")


def _run_flow(settings: Settings) -> Browser:
    browser = Browser()
    callback = _authorize_until_callback(browser, settings)
    home = browser.follow(browser.follow(callback))  # /callback → / (トップページ)
    assert home.status == 200
    assert "受け取ったトークン" in home.text

    profile = _get_profile(browser, settings)
    assert profile.status == 200
    assert "alice@example.com" in profile.text
    notes = browser.request(settings.client_base_url + "/api/notes")
    assert "読書メモ" in notes.text
    return browser


def test_e2e_flow_without_pkce(running_without_pkce: Settings) -> None:
    _run_flow(running_without_pkce)


def test_e2e_flow_with_pkce(running_with_pkce: Settings) -> None:
    _run_flow(running_with_pkce)


def test_e2e_tampered_state_is_rejected(running_without_pkce: Settings) -> None:
    settings = running_without_pkce
    browser = Browser()
    callback = _authorize_until_callback(browser, settings)
    assert callback.location is not None
    tampered = re.sub(r"state=[^&]+", "state=attacker", callback.location)
    page = browser.request(tampered)
    assert page.status == 400
    assert "state が一致しません" in page.text


def test_e2e_code_cannot_be_reused(running_without_pkce: Settings) -> None:
    settings = running_without_pkce
    browser = Browser()
    callback = _authorize_until_callback(browser, settings)
    assert callback.location is not None
    code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(callback.location).query))["code"]
    browser.follow(callback)

    # 同じ認可コードでもう一度トークンを要求すると invalid_grant になる
    request = urllib.request.Request(
        settings.token_endpoint,
        data=urllib.parse.urlencode(
            {"grant_type": "authorization_code", "code": code, "redirect_uri": settings.redirect_uri}
        ).encode(),
        headers={"Authorization": encode_basic_auth(config.CLIENT_ID, config.CLIENT_SECRET)},
    )
    try:
        urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10)
        raise AssertionError("2 回目の交換は失敗するはずです")
    except urllib.error.HTTPError as err:
        assert err.code == 400
        assert json.loads(err.read())["error"] == "invalid_grant"
    # 再利用が検知されたので、1 回目で発行されたトークンも失効している
    assert "ステータス <strong>401</strong>" in _get_profile(browser, settings).text


def test_e2e_refresh(running_with_pkce: Settings) -> None:
    settings = running_with_pkce
    browser = _run_flow(settings)
    page = browser.request(settings.client_base_url + "/refresh", {})
    home = browser.follow(page)
    assert "リフレッシュトークンで新しいアクセストークンを取得しました" in home.text
    assert _get_profile(browser, settings).status == 200

