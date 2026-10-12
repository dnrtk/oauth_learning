"""クライアント (Client) = ユーザーのデータを使いたい第三者アプリ。

この教材では「メモ閲覧アプリ」という Web アプリを想定しています。
ユーザーのパスワードは一切受け取らず、認可サーバーから受け取ったアクセストークンで
リソースサーバーの API を呼び出します。

エンドポイント:
  GET  /             トップページ (トークンの状態と操作ボタン)
  GET  /login        「連携する」ボタン。認可サーバーへリダイレクトする
  GET  /callback     認可サーバーから認可コードを受け取る (redirect_uri)
  GET  /api/profile  リソースサーバーのプロフィール API を呼ぶ
  GET  /api/notes    リソースサーバーのメモ API を呼ぶ
  POST /refresh      リフレッシュトークンでアクセストークンを更新する
  POST /logout       クライアントのセッションを破棄する
"""

from __future__ import annotations

import secrets
import time
import urllib.parse
from dataclasses import dataclass, field

from .. import config
from ..common import (
    HttpResult,
    JsonDict,
    OAuthError,
    Request,
    Response,
    SessionStore,
    encode_basic_auth,
    esc,
    html_page,
    http_request,
    pretty_json,
    redirect,
)
from ..config import Settings
from . import pkce


# ===========================================================================
# データ構造
# ===========================================================================
@dataclass
class TokenSet:
    """トークンエンドポイントから受け取ったトークン一式。"""

    access_token: str
    token_type: str
    expires_at: float | None
    refresh_token: str | None
    scope: str | None
    raw: JsonDict

    @classmethod
    def from_response(cls, body: JsonDict) -> TokenSet:
        expires_in = body.get("expires_in")
        return cls(
            access_token=str(body["access_token"]),
            token_type=str(body.get("token_type", "")),
            expires_at=time.time() + int(expires_in) if expires_in is not None else None,
            refresh_token=body.get("refresh_token"),
            scope=body.get("scope"),
            raw=body,
        )


@dataclass
class ClientSession:
    """クライアント (メモ閲覧アプリ) 側のセッション。認可サーバーのセッションとは別物。"""

    state: str | None = None
    code_verifier: str | None = None
    tokens: TokenSet | None = None
    messages: list[str] = field(default_factory=list)


# ===========================================================================
# 演習で実装する関数
# ===========================================================================
def build_authorization_url(settings: Settings, state: str, code_challenge: str | None) -> str:
    """認可サーバーの認可エンドポイントへ飛ばすための URL を組み立てる。"""
    # [演習 1-1] 認可リクエストの URL を組み立てる
    # HINT: 行き先は settings.authorization_endpoint です。
    # HINT: 付けるクエリパラメータ (RFC 6749 4.1.1):
    # HINT:   response_type = "code"               … 認可コードフローを使うという宣言
    # HINT:   client_id     = config.CLIENT_ID     … どのアプリからの依頼か
    # HINT:   redirect_uri  = settings.redirect_uri … 認可コードの返送先
    # HINT:   scope         = config.CLIENT_SCOPE  … どんな権限が欲しいか
    # HINT:   state         = state                … CSRF 対策のランダム値
    # HINT: code_challenge が None でなければ、code_challenge と code_challenge_method="S256" も付けます (演習 7 で使用)。
    # HINT: 値のエンコードには urllib.parse.urlencode(dict) が使えます。
    params = {
        "response_type": "code",
        "client_id": config.CLIENT_ID,
        "redirect_uri": settings.redirect_uri,
        "scope": config.CLIENT_SCOPE,
        "state": state,
    }
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    return settings.authorization_endpoint + "?" + urllib.parse.urlencode(params)
    # [/演習 1-1]


def verify_state(expected: str | None, received: str | None) -> bool:
    """コールバックで返ってきた state が、自分が送ったものと一致するか確かめる。"""
    # [演習 4-1] state を検証する
    # HINT: どちらかが None なら False (自分が始めていないフローのコールバックかもしれない)。
    # HINT: 比較は secrets.compare_digest(expected.encode(), received.encode()) を使います。
    if expected is None or received is None:
        return False
    return secrets.compare_digest(expected.encode(), received.encode())
    # [/演習 4-1]


def post_to_token_endpoint(settings: Settings, form: dict[str, str]) -> JsonDict:
    """トークンエンドポイントへ POST する (クライアント認証付き)。エラー応答なら OAuthError を送出する。"""
    result = http_request(
        "client",
        "POST",
        settings.token_endpoint,
        form=form,
        # クライアント認証: 「私は本物の demo-client です」と client_secret で証明する (RFC 6749 2.3.1)
        headers={"Authorization": encode_basic_auth(config.CLIENT_ID, config.CLIENT_SECRET)},
    )
    if result.status != 200:
        raise OAuthError(
            str(result.body.get("error", "unknown_error")),
            str(result.body.get("error_description", "")),
            result.status,
        )
    return result.body


def exchange_code_for_token(settings: Settings, code: str, code_verifier: str | None) -> JsonDict:
    """認可コードをアクセストークンと交換する。"""
    # [演習 4-2] 認可コードをトークンと交換する
    # HINT: post_to_token_endpoint(settings, form) を呼び、その戻り値を返します。
    # HINT: form に入れるもの (RFC 6749 4.1.3):
    # HINT:   grant_type   = "authorization_code"
    # HINT:   code         = 受け取った認可コード
    # HINT:   redirect_uri = settings.redirect_uri (認可リクエストと同じ値)
    # HINT: code_verifier が None でなければ form["code_verifier"] にも入れます (演習 7 で使用)。
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirect_uri,
    }
    if code_verifier is not None:
        form["code_verifier"] = code_verifier
    return post_to_token_endpoint(settings, form)
    # [/演習 4-2]


def call_resource_api(settings: Settings, path: str, access_token: str) -> HttpResult:
    """アクセストークンを付けてリソースサーバーの API を呼ぶ。"""
    # [演習 6-5] アクセストークンを付けて API を呼ぶ
    # HINT: http_request("client", "GET", settings.resource_base_url + path, headers=...) の結果を返します。
    # HINT: ヘッダーは {"Authorization": "Bearer " + access_token} (RFC 6750 2.1)。
    return http_request(
        "client",
        "GET",
        settings.resource_base_url + path,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    # [/演習 6-5]


def refresh_access_token(settings: Settings, refresh_token: str) -> JsonDict:
    """リフレッシュトークンを使って新しいアクセストークンを取得する。"""
    # [演習 8-2] リフレッシュトークンでトークンを更新する
    # HINT: 演習 4-2 と同じく post_to_token_endpoint() を使います。
    # HINT: form は grant_type = "refresh_token", refresh_token = refresh_token (RFC 6749 6)。
    return post_to_token_endpoint(
        settings, {"grant_type": "refresh_token", "refresh_token": refresh_token}
    )
    # [/演習 8-2]


# ===========================================================================
# クライアント本体 (HTTP ハンドラー、演習対象外)
# ===========================================================================
class ClientApp:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.sessions = SessionStore[ClientSession]("client_session", ClientSession)

    def handle(self, request: Request) -> Response:
        session_id, session = self.sessions.load(request)
        match (request.method, request.path):
            case ("GET", "/"):
                response = self._home(session)
            case ("GET", "/login"):
                response = self._login(session)
            case ("GET", "/callback"):
                response = self._callback(request, session)
            case ("GET", "/api/profile"):
                response = self._call_api(session, "/api/profile")
            case ("GET", "/api/notes"):
                response = self._call_api(session, "/api/notes")
            case ("POST", "/refresh"):
                response = self._refresh(session)
            case ("POST", "/logout"):
                session.tokens = None
                session.messages.append("クライアントからログアウトしました (認可サーバーのログインは残っています)。")
                response = redirect("/")
            case _:
                response = html_page("client", "Not Found", "<p>ページが見つかりません。</p>", status=404)
        return self.sessions.attach(response, session_id)

    def _login(self, session: ClientSession) -> Response:
        # state: このブラウザで始めたフローであることを後で確かめるためのランダム値
        session.state = secrets.token_urlsafe(32)
        code_challenge: str | None = None
        if self.settings.use_pkce:
            # code_verifier は手元 (セッション) に隠し、ハッシュ値 (code_challenge) だけを送る
            session.code_verifier = pkce.generate_code_verifier()
            code_challenge = pkce.compute_code_challenge(session.code_verifier)
        else:
            session.code_verifier = None
        return redirect(build_authorization_url(self.settings, session.state, code_challenge))

    def _callback(self, request: Request, session: ClientSession) -> Response:
        # ① state の検証。一致しなければ、攻撃者が仕込んだコールバックの可能性がある (CSRF)
        if not verify_state(session.state, request.query.get("state")):
            return self._error_page(
                "state が一致しません",
                "このコールバックは、このブラウザで開始した認可フローのものではありません。"
                "CSRF 攻撃の可能性があるため処理を中止しました。",
            )
        session.state = None  # state は使い捨て

        # ② 認可サーバーがエラーを返してきた場合 (ユーザーが拒否した等)
        if "error" in request.query:
            return self._error_page(
                f"認可サーバーからのエラー: {request.query['error']}",
                request.query.get("error_description", ""),
            )

        code = request.query.get("code")
        if not code:
            return self._error_page("認可コードがありません", "コールバックに code パラメータが含まれていません。")

        # ③ 認可コードをトークンと交換する (ここだけはブラウザを経由しない直接通信)
        try:
            body = exchange_code_for_token(self.settings, code, session.code_verifier)
        except OAuthError as exc:
            return self._error_page(f"トークンの取得に失敗しました: {exc.error}", exc.description)
        finally:
            session.code_verifier = None
        session.tokens = TokenSet.from_response(body)
        session.messages.append("認可コードをアクセストークンと交換しました。")
        return redirect("/")

    def _call_api(self, session: ClientSession, path: str) -> Response:
        if session.tokens is None:
            return redirect("/")
        result = call_resource_api(self.settings, path, session.tokens.access_token)
        css = "success" if result.status == 200 else "error"
        hint = ""
        if result.status == 401:
            hint = (
                '<div class="card note"><p>アクセストークンが期限切れ、または取り消された可能性があります。'
                "トップページの「トークンを更新」を試してください。</p></div>"
            )
        elif result.status == 403:
            hint = '<div class="card note"><p>トークンは有効ですが、この API に必要なスコープがありません。</p></div>'
        www_authenticate = result.headers.get("www-authenticate")
        header_html = (
            f"<p>WWW-Authenticate: <code>{esc(www_authenticate)}</code></p>" if www_authenticate else ""
        )
        body = f"""
<div class="card {css}">
<p><code>GET {esc(self.settings.resource_base_url + path)}</code> → ステータス <strong>{result.status}</strong></p>
{header_html}
<pre><code class="language-json">{esc(pretty_json(result.body))}</code></pre>
</div>
{hint}
<p><a class="button secondary" href="/">トップへ戻る</a></p>"""
        return html_page("client", "API の呼び出し結果", body)

    def _refresh(self, session: ClientSession) -> Response:
        if session.tokens is None or session.tokens.refresh_token is None:
            return redirect("/")
        try:
            body = refresh_access_token(self.settings, session.tokens.refresh_token)
        except OAuthError as exc:
            session.tokens = None
            return self._error_page(
                f"トークンの更新に失敗しました: {exc.error}",
                f"{exc.description} もう一度「連携する」からやり直してください。",
            )
        session.tokens = TokenSet.from_response(body)
        session.messages.append("リフレッシュトークンで新しいアクセストークンを取得しました。")
        return redirect("/")

    def _error_page(self, title: str, detail: str) -> Response:
        body = f"""
<div class="card error"><p><strong>{esc(title)}</strong></p><p>{esc(detail)}</p></div>
<p><a class="button secondary" href="/">トップへ戻る</a></p>"""
        return html_page("client", "エラー", body, status=400)

    def _home(self, session: ClientSession) -> Response:
        messages = "".join(f'<div class="card success"><p>{esc(m)}</p></div>' for m in session.messages)
        session.messages.clear()
        tokens = session.tokens
        if tokens is None:
            body = f"""
{messages}
<div class="card">
<p>このアプリは、リソースサーバーに保存されている <strong>あなたのプロフィールとメモ</strong> を表示します。</p>
<p>そのためにはあなたの許可が必要です。下のボタンを押すと <strong>認可サーバー</strong> へ移動します。</p>
<p><a class="button" href="/login">認可サーバーと連携する</a></p>
</div>
<div class="card note">
<p>このアプリはあなたのパスワードを聞きません。ログインは認可サーバーの画面で行い、
このアプリが受け取るのは「アクセストークン」という <strong>限定された権限の鍵</strong> だけです。</p>
<p class="muted">PKCE: {"有効" if self.settings.use_pkce else "無効 (--no-pkce)"}</p>
</div>"""
        else:
            remaining = (
                f"残り {int(tokens.expires_at - time.time())} 秒" if tokens.expires_at is not None else "不明"
            )
            body = f"""
{messages}
<div class="card">
<h2>受け取ったトークン</h2>
<div class="table-wrap"><table>
<tr><th>access_token</th><td><code>{esc(tokens.access_token)}</code></td></tr>
<tr><th>token_type</th><td>{esc(tokens.token_type)}</td></tr>
<tr><th>有効期限</th><td>{esc(remaining)}</td></tr>
<tr><th>scope</th><td>{esc(tokens.scope)}</td></tr>
<tr><th>refresh_token</th><td><code>{esc(tokens.refresh_token)}</code></td></tr>
</table></div>
<details><summary>トークンレスポンスの JSON 全体</summary>
<pre><code class="language-json">{esc(pretty_json(tokens.raw))}</code></pre></details>
</div>
<div class="card">
<h2>リソースサーバーの API を呼ぶ</h2>
<p><a class="button" href="/api/profile">プロフィールを取得</a>
<a class="button" href="/api/notes">メモを取得</a></p>
<form method="post" action="/refresh" class="inline"><button type="submit" class="secondary">トークンを更新 (refresh)</button></form>
<form method="post" action="/logout" class="inline"><button type="submit" class="secondary">ログアウト</button></form>
</div>
<div class="card note">
<p>学習用にトークンをそのまま表示していますが、本物のアプリではトークンを画面やログに出してはいけません。</p>
</div>"""
        return html_page("client", "メモ閲覧アプリ", body)
