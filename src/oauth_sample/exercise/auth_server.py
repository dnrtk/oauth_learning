# ============================================================================
# 演習用ファイルです。「TODO」と書かれた箇所を実装してください。
# 解答は src/oauth_sample/solution/ の同名ファイルにあります。
# ============================================================================
"""認可サーバー (Authorization Server)。

役割:
  - リソースオーナー (ユーザー) をログインさせ、クライアントへのアクセス許可 (同意) を得る
  - 認可コードを発行し、クライアントからの求めに応じてアクセストークンと交換する
  - リソースサーバーからの「このトークンは有効？」という問い合わせに答える

エンドポイント:
  GET  /authorize           認可エンドポイント (ブラウザ経由で届く = フロントチャネル)
  GET  /login, POST /login  認可サーバー自身のログイン画面
  POST /authorize/decision  同意画面の「許可する」「拒否する」の送信先
  POST /token               トークンエンドポイント (クライアントが直接呼ぶ = バックチャネル)
  POST /introspect          トークンイントロスペクション (リソースサーバーが直接呼ぶ, RFC 7662)
  GET  /                    内部状態を確認できる学習用ダッシュボード
  POST /grants/revoke       ダッシュボードから許可を取り消す
  POST /logout              認可サーバーからログアウト
"""

from __future__ import annotations

import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field, replace

from .. import config
from ..common import (
    JsonDict,
    OAuthError,
    Request,
    Response,
    SessionStore,
    add_query_params,
    decode_basic_auth,
    esc,
    html_page,
    json_response,
    redirect,
)
from ..config import ClientRegistration, Settings
from . import pkce

# code_challenge は SHA-256 (32 バイト) を Base64URL 化したものなので必ず 43 文字
CODE_CHALLENGE_PATTERN = re.compile(r"[A-Za-z0-9\-_]{43}")


# ===========================================================================
# データ構造
# ===========================================================================
@dataclass(frozen=True)
class AuthorizationRequest:
    """検証済みの認可リクエスト。同意画面を挟む間、セッションに保存しておく。"""

    client_id: str
    redirect_uri: str
    scope: str  # スペース区切り (例: "profile notes:read")
    state: str | None
    code_challenge: str | None = None


@dataclass
class AuthorizationCodeRecord:
    """発行した認可コードと、それに紐づく情報。"""

    code: str
    client_id: str
    redirect_uri: str
    username: str
    scope: str
    expires_at: float
    code_challenge: str | None
    used: bool = False


@dataclass
class AccessTokenRecord:
    token: str
    client_id: str
    username: str
    scope: str
    expires_at: float
    grant_id: str  # どの「許可」から発行されたか (最初の認可コードの値)
    revoked: bool = False


@dataclass
class RefreshTokenRecord:
    token: str
    client_id: str
    username: str
    scope: str
    expires_at: float
    grant_id: str
    revoked: bool = False


@dataclass
class AuthServerSession:
    """認可サーバー自身のログインセッション (クライアントのセッションとは別物)。"""

    username: str | None = None
    pending: dict[str, AuthorizationRequest] = field(default_factory=dict)


class UntrustedRedirectError(Exception):
    """client_id や redirect_uri が不正なため、クライアントへリダイレクトしてはいけないエラー。"""


# ===========================================================================
# 認可エンドポイントで使う関数
# ===========================================================================
def validate_authorization_request(
    query: dict[str, str], clients: dict[str, ClientRegistration]
) -> AuthorizationRequest:
    """認可リクエスト (GET /authorize のクエリ) を検証し、AuthorizationRequest を返す。"""
    # [演習 2-1] 認可リクエストを検証する
    # TODO: ここを実装してください
    # ヒント: ① client_id が clients に登録されているか → 不正なら UntrustedRedirectError を送出
    # ヒント: ② redirect_uri が登録値 (client.redirect_uris) と「完全一致」するか → 不正なら UntrustedRedirectError
    # ヒント:    ※ ①② は必ず最初に検証します。ここが不正なのにリダイレクトすると攻撃者のサイトへ誘導されてしまいます。
    # ヒント: ③ response_type が "code" か → 不正なら OAuthError("unsupported_response_type", "説明")
    # ヒント: ④ scope (スペース区切り) が空でなく、すべて client.allowed_scopes に含まれるか
    # ヒント:    → 不正なら OAuthError("invalid_scope", "説明")
    # ヒント: ⑤ 問題なければ AuthorizationRequest(...) を返す。state は無ければ None。
    raise NotImplementedError("演習 2-1: 認可リクエストを検証する")
    # [/演習 2-1]


def extract_pkce_challenge(query: dict[str, str]) -> str:
    """認可リクエストから PKCE の code_challenge を取り出して検証する。"""
    # [演習 7-4] code_challenge を受け取る
    # TODO: ここを実装してください
    # ヒント: query の "code_challenge" が無ければ OAuthError("invalid_request", "説明")
    # ヒント: "code_challenge_method" は "S256" のみ受け付ける (省略時は "plain" 扱いなのでエラー)
    # ヒント: 形式チェックには CODE_CHALLENGE_PATTERN.fullmatch() を使う
    raise NotImplementedError("演習 7-4: code_challenge を受け取る")
    # [/演習 7-4]


def build_authorization_response_url(redirect_uri: str, code: str, state: str | None) -> str:
    """認可コードをクライアントへ返すためのリダイレクト先 URL を作る。"""
    # [演習 3-2] 認可レスポンスの URL を組み立てる
    # TODO: ここを実装してください
    # ヒント: redirect_uri に code と state (あれば) をクエリパラメータとして付けます。
    # ヒント: common.add_query_params(url, {"key": "value"}) が使えます。
    # ヒント: state は受け取った値を「そのまま」返します。クライアントはこれで CSRF を検知します。
    raise NotImplementedError("演習 3-2: 認可レスポンスの URL を組み立てる")
    # [/演習 3-2]


# ===========================================================================
# 認可サーバー本体
# ===========================================================================
class AuthorizationServer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.clients = config.registered_clients(settings)
        self.codes: dict[str, AuthorizationCodeRecord] = {}
        self.access_tokens: dict[str, AccessTokenRecord] = {}
        self.refresh_tokens: dict[str, RefreshTokenRecord] = {}
        # 複数リクエストが同時に来ても辞書の整合性が崩れないようにするロック
        self.lock = threading.RLock()
        self.sessions = SessionStore[AuthServerSession]("as_session", AuthServerSession)

    # ------------------------------------------------------------------
    # 演習で実装するメソッド
    # ------------------------------------------------------------------
    def issue_authorization_code(self, auth_request: AuthorizationRequest, username: str) -> str:
        """ユーザーが同意したので、認可コードを発行して保存し、その値を返す。"""
        # [演習 3-1] 認可コードを発行する
        # TODO: ここを実装してください
        # ヒント: 推測できないランダムな文字列を secrets.token_urlsafe(32) で作ります。
        # ヒント: AuthorizationCodeRecord を作って self.codes[code] に保存します (with self.lock: の中で)。
        # ヒント: 有効期限は time.time() + config.AUTHORIZATION_CODE_TTL_SECONDS (短命にするのが鉄則)。
        # ヒント: client_id / redirect_uri / scope / code_challenge は auth_request から引き継ぎます。
        raise NotImplementedError("演習 3-1: 認可コードを発行する")
        # [/演習 3-1]

    def authenticate_client(self, request: Request) -> ClientRegistration:
        """トークンエンドポイントに来たクライアントが本物か (client_secret を知っているか) を確かめる。"""
        # [演習 5-1] クライアントを認証する
        # TODO: ここを実装してください
        # ヒント: common.decode_basic_auth(request.header("Authorization")) で (client_id, client_secret) が取れます。
        # ヒント: 取れない / 未登録の client_id / secret 不一致 → OAuthError("invalid_client", "説明", status=401)
        # ヒント: secret の比較は secrets.compare_digest(a.encode(), b.encode()) を使います。
        raise NotImplementedError("演習 5-1: クライアントを認証する")
        # [/演習 5-1]

    def redeem_authorization_code(
        self, form: dict[str, str], client: ClientRegistration
    ) -> AuthorizationCodeRecord:
        """トークンリクエストの認可コードを検証し、使用済みにして、そのレコードを返す。"""
        # [演習 5-2] 認可コードを検証して使用済みにする
        # TODO: ここを実装してください
        # ヒント: form["code"] が無い → OAuthError("invalid_request", ...)
        # ヒント: 以下はすべて OAuthError("invalid_grant", "説明") にします。
        # ヒント:   - self.codes に存在しない
        # ヒント:   - すでに使用済み (record.used)。再利用は漏洩の兆候なので self.revoke_grant(record.code) も呼ぶ
        # ヒント:   - 有効期限切れ
        # ヒント:   - 別のクライアントに発行されたコード (record.client_id != client.client_id)
        # ヒント:   - form["redirect_uri"] が認可リクエスト時と違う
        # ヒント:   - record.code_challenge があるのに pkce.verify_pkce(form.get("code_verifier"), ...) が False
        # ヒント:     (PKCE の中身は演習 7 で作ります。--no-pkce で動かしている間は code_challenge は None です)
        # ヒント: すべて OK なら record.used = True にして record を返します。全体を with self.lock: で囲みます。
        raise NotImplementedError("演習 5-2: 認可コードを検証して使用済みにする")
        # [/演習 5-2]

    def issue_tokens(self, username: str, client_id: str, scope: str, grant_id: str) -> JsonDict:
        """アクセストークンとリフレッシュトークンを発行・保存し、トークンレスポンス (JSON) を返す。"""
        # [演習 5-3] トークンを発行する
        # TODO: ここを実装してください
        # ヒント: アクセストークン・リフレッシュトークンともに secrets.token_urlsafe(32) で作ります。
        # ヒント: AccessTokenRecord / RefreshTokenRecord を作って self.access_tokens / self.refresh_tokens に保存します。
        # ヒント: 有効期限は config.ACCESS_TOKEN_TTL_SECONDS / config.REFRESH_TOKEN_TTL_SECONDS を使います。
        # ヒント: 返す JSON (RFC 6749 5.1) のキー: access_token, token_type ("Bearer"), expires_in, refresh_token, scope
        raise NotImplementedError("演習 5-3: トークンを発行する")
        # [/演習 5-3]

    def introspect(self, token: str) -> JsonDict:
        """アクセストークンの状態を返す (RFC 7662)。リソースサーバーからの問い合わせに使う。"""
        # [演習 6-1] トークンイントロスペクション
        # TODO: ここを実装してください
        # ヒント: self.access_tokens から探し、存在しない / 失効済み (revoked) / 期限切れ なら {"active": False} を返す。
        # ヒント: 有効なら {"active": True, "scope": ..., "client_id": ..., "username": ..., "exp": 有効期限(整数)} を返す。
        # ヒント: 無効な理由は返しません。攻撃者にヒントを与えないためです。
        raise NotImplementedError("演習 6-1: トークンイントロスペクション")
        # [/演習 6-1]

    def exchange_refresh_token(self, form: dict[str, str], client: ClientRegistration) -> JsonDict:
        """リフレッシュトークンを検証し、新しいトークンを発行する (リフレッシュトークンローテーション付き)。"""
        # [演習 8-1] リフレッシュトークンで再発行する
        # TODO: ここを実装してください
        # ヒント: form["refresh_token"] が無い → OAuthError("invalid_request", ...)
        # ヒント: 以下は OAuthError("invalid_grant", "説明"):
        # ヒント:   - self.refresh_tokens に存在しない / 別クライアントのもの / 期限切れ
        # ヒント:   - 失効済み (revoked)。使用済みのものが再び来た = 盗用の可能性があるので self.revoke_grant(record.grant_id) も呼ぶ
        # ヒント: OK なら古いリフレッシュトークンを revoked = True にして (ローテーション)、
        # ヒント: self.issue_tokens(record.username, record.client_id, record.scope, record.grant_id) の結果を返す。
        raise NotImplementedError("演習 8-1: リフレッシュトークンで再発行する")
        # [/演習 8-1]

    # ------------------------------------------------------------------
    # 補助メソッド (演習対象外)
    # ------------------------------------------------------------------
    def revoke_grant(self, grant_id: str) -> None:
        """ある「許可」から発行されたトークンをすべて失効させる。"""
        with self.lock:
            for access in self.access_tokens.values():
                if access.grant_id == grant_id:
                    access.revoked = True
            for refresh in self.refresh_tokens.values():
                if refresh.grant_id == grant_id:
                    refresh.revoked = True

    # ------------------------------------------------------------------
    # HTTP ハンドラー (演習対象外)
    # ------------------------------------------------------------------
    def handle(self, request: Request) -> Response:
        match (request.method, request.path):
            case ("GET", "/"):
                return self._dashboard(request)
            case ("GET", "/authorize"):
                return self._authorize(request)
            case ("GET", "/login"):
                return self._login_form(request.query.get("next", "/"))
            case ("POST", "/login"):
                return self._login(request)
            case ("POST", "/authorize/decision"):
                return self._decision(request)
            case ("POST", "/token"):
                return self._token(request)
            case ("POST", "/introspect"):
                return self._introspect(request)
            case ("POST", "/grants/revoke"):
                return self._revoke(request)
            case ("POST", "/logout"):
                return self._logout(request)
            case _:
                return html_page("auth", "Not Found", "<p>ページが見つかりません。</p>", status=404)

    def _authorize(self, request: Request) -> Response:
        """認可エンドポイント。リクエストを検証し、未ログインならログイン画面、ログイン済みなら同意画面へ。"""
        try:
            auth_request = validate_authorization_request(request.query, self.clients)
            if self.settings.use_pkce:
                auth_request = replace(
                    auth_request, code_challenge=extract_pkce_challenge(request.query)
                )
        except UntrustedRedirectError as exc:
            # redirect_uri が信用できないので、クライアントへは戻さずにここでエラーを表示する
            return html_page(
                "auth",
                "認可リクエストのエラー",
                f'<div class="card error"><p>{esc(exc)}</p></div>'
                '<div class="card note"><p>client_id または redirect_uri が不正なため、'
                "クライアントへはリダイレクトしません。もしリダイレクトすると、攻撃者が用意した URL へ"
                "ユーザーを誘導する踏み台 (オープンリダイレクタ) になってしまいます。</p></div>",
                status=400,
            )
        except OAuthError as exc:
            # redirect_uri は検証済みなので、エラー内容をクライアントへ返してよい (RFC 6749 4.1.2.1)
            params = exc.to_json()
            if "state" in request.query:
                params["state"] = request.query["state"]
            return redirect(add_query_params(request.query["redirect_uri"], params))

        session_id, session = self.sessions.load(request)
        if session.username is None:
            next_url = "/authorize?" + urllib.parse.urlencode(request.query)
            response = redirect("/login?" + urllib.parse.urlencode({"next": next_url}))
        else:
            request_id = secrets.token_urlsafe(16)
            with self.lock:
                session.pending[request_id] = auth_request
            response = self._consent_page(session.username, request_id, auth_request)
        return self.sessions.attach(response, session_id)

    def _login_form(self, next_url: str, error: str | None = None) -> Response:
        error_html = f'<div class="card error"><p>{esc(error)}</p></div>' if error else ""
        users = "、".join(f"<code>{esc(u)}</code> / <code>{esc(p)}</code>" for u, p in config.USERS.items())
        body = f"""
{error_html}
<div class="card">
<form method="post" action="/login">
  <input type="hidden" name="next" value="{esc(next_url)}">
  <label>ユーザー名 <input type="text" name="username" autocomplete="username"></label>
  <label>パスワード <input type="password" name="password" autocomplete="current-password"></label>
  <button type="submit">ログイン</button>
</form>
<p class="muted">デモ用アカウント: {users}</p>
</div>
<div class="card note">
<p>ここは <strong>認可サーバー</strong> のログイン画面です (画面上部の色帯とアドレスバーを確認してください)。
パスワードを入力する相手はクライアント (メモ閲覧アプリ) ではなく認可サーバーです。
これこそが OAuth の目的で、クライアントはあなたのパスワードを一切知りません。</p>
</div>"""
        status = 401 if error else 200
        return html_page("auth", "認可サーバーにログイン", body, status=status)

    def _login(self, request: Request) -> Response:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        next_url = request.form.get("next", "/")
        # オープンリダイレクト対策: ログイン後の戻り先は自サーバー内の決まったパスだけに限定する
        if not (next_url == "/" or next_url.startswith("/authorize?")):
            next_url = "/"
        expected = config.USERS.get(username)
        if expected is None or not secrets.compare_digest(expected.encode(), password.encode()):
            return self._login_form(next_url, "ユーザー名またはパスワードが違います")
        session_id, session = self.sessions.load(request)
        session.username = username
        return self.sessions.attach(redirect(next_url), session_id)

    def _consent_page(
        self, username: str, request_id: str, auth_request: AuthorizationRequest
    ) -> Response:
        client = self.clients[auth_request.client_id]
        scopes = "".join(
            f"<li>{esc(config.SCOPE_DESCRIPTIONS.get(s, s))} <code>{esc(s)}</code></li>"
            for s in auth_request.scope.split()
        )
        body = f"""
<div class="card">
<p><strong>{esc(username)}</strong> さんとしてログイン中です。</p>
<p><strong>{esc(client.client_name)}</strong> が、あなたのアカウントへの次のアクセスを求めています。</p>
<ul>{scopes}</ul>
<form method="post" action="/authorize/decision" class="inline">
  <input type="hidden" name="request_id" value="{esc(request_id)}">
  <button type="submit" name="decision" value="approve">許可する</button>
  <button type="submit" name="decision" value="deny" class="secondary">拒否する</button>
</form>
</div>
<div class="card note">
<p>これが <strong>同意画面</strong> です。「許可する」を押すと、認可サーバーは <strong>認可コード</strong> を発行し、
ブラウザを <code>{esc(auth_request.redirect_uri)}</code> へリダイレクトさせます。</p>
<p class="muted">受け取った state: <code>{esc(auth_request.state)}</code><br>
受け取った code_challenge: <code>{esc(auth_request.code_challenge)}</code></p>
</div>"""
        return html_page("auth", "アクセスの許可", body)

    def _decision(self, request: Request) -> Response:
        session_id, session = self.sessions.load(request)
        with self.lock:
            auth_request = session.pending.pop(request.form.get("request_id", ""), None)
        if auth_request is None or session.username is None:
            return html_page(
                "auth",
                "不正なリクエスト",
                '<div class="card error"><p>認可リクエストが見つかりません。最初からやり直してください。</p></div>',
                status=400,
            )
        if request.form.get("decision") == "approve":
            code = self.issue_authorization_code(auth_request, session.username)
            location = build_authorization_response_url(auth_request.redirect_uri, code, auth_request.state)
        else:
            params = {"error": "access_denied", "error_description": "ユーザーがアクセスを拒否しました"}
            if auth_request.state is not None:
                params["state"] = auth_request.state
            location = add_query_params(auth_request.redirect_uri, params)
        return self.sessions.attach(redirect(location), session_id)

    def _token(self, request: Request) -> Response:
        """トークンエンドポイント。クライアントが (ブラウザを介さず) 直接呼び出す。"""
        try:
            client = self.authenticate_client(request)
            grant_type = request.form.get("grant_type")
            if grant_type == "authorization_code":
                record = self.redeem_authorization_code(request.form, client)
                body = self.issue_tokens(record.username, record.client_id, record.scope, grant_id=record.code)
            elif grant_type == "refresh_token":
                body = self.exchange_refresh_token(request.form, client)
            else:
                raise OAuthError("unsupported_grant_type", f"未対応の grant_type です: {grant_type}")
        except OAuthError as exc:
            headers = [("WWW-Authenticate", 'Basic realm="oauth-sample"')] if exc.status == 401 else []
            return json_response(exc.to_json(), status=exc.status, headers=headers)
        return json_response(body)

    def _introspect(self, request: Request) -> Response:
        """イントロスペクションエンドポイント。登録済みのリソースサーバーだけが呼び出せる。"""
        credentials = decode_basic_auth(request.header("Authorization"))
        valid = credentials is not None and secrets.compare_digest(
            f"{credentials[0]}:{credentials[1]}".encode(),
            f"{config.RESOURCE_SERVER_ID}:{config.RESOURCE_SERVER_SECRET}".encode(),
        )
        if not valid:
            return json_response(
                {"error": "invalid_client"},
                status=401,
                headers=[("WWW-Authenticate", 'Basic realm="oauth-sample"')],
            )
        return json_response(self.introspect(request.form.get("token", "")))

    def _revoke(self, request: Request) -> Response:
        self.revoke_grant(request.form.get("grant_id", ""))
        return redirect("/")

    def _logout(self, request: Request) -> Response:
        session_id, session = self.sessions.load(request)
        session.username = None
        return self.sessions.attach(redirect("/"), session_id)

    def _dashboard(self, request: Request) -> Response:
        session_id, session = self.sessions.load(request)
        now = time.time()

        def remaining(expires_at: float) -> str:
            seconds = int(expires_at - now)
            return f"残り {seconds} 秒" if seconds > 0 else "期限切れ"

        def short(value: str) -> str:
            return f"<code>{esc(value[:10])}…</code>"

        with self.lock:
            code_rows = "".join(
                f"<tr><td>{short(r.code)}</td><td>{esc(r.username)}</td><td>{esc(r.scope)}</td>"
                f"<td>{'使用済み' if r.used else '未使用'}</td><td>{remaining(r.expires_at)}</td></tr>"
                for r in self.codes.values()
            )
            token_rows = "".join(
                f"<tr><td>{short(t.token)}</td><td>{esc(t.username)}</td><td>{esc(t.scope)}</td>"
                f"<td>{'失効' if t.revoked else '有効'}</td><td>{remaining(t.expires_at)}</td>"
                f'<td><form method="post" action="/grants/revoke" class="inline">'
                f'<input type="hidden" name="grant_id" value="{esc(t.grant_id)}">'
                f'<button type="submit" class="secondary">許可を取り消す</button></form></td></tr>'
                for t in self.access_tokens.values()
            )
            refresh_rows = "".join(
                f"<tr><td>{short(t.token)}</td><td>{esc(t.username)}</td>"
                f"<td>{'失効/使用済み' if t.revoked else '有効'}</td><td>{remaining(t.expires_at)}</td></tr>"
                for t in self.refresh_tokens.values()
            )
        empty = '<tr><td colspan="6" class="muted">なし</td></tr>'
        login_state = (
            f"<p><strong>{esc(session.username)}</strong> としてログイン中</p>"
            '<form method="post" action="/logout"><button type="submit" class="secondary">認可サーバーからログアウト</button></form>'
            if session.username
            else '<p>ログインしていません。</p><p><a class="button" href="/login">ログイン</a></p>'
        )
        body = f"""
<div class="card"><h2>このブラウザのログイン状態</h2>{login_state}</div>
<div class="card"><h2>発行した認可コード</h2><div class="table-wrap"><table>
<tr><th>コード</th><th>ユーザー</th><th>スコープ</th><th>状態</th><th>有効期限</th></tr>
{code_rows or empty}</table></div></div>
<div class="card"><h2>発行したアクセストークン</h2><div class="table-wrap"><table>
<tr><th>トークン</th><th>ユーザー</th><th>スコープ</th><th>状態</th><th>有効期限</th><th>操作</th></tr>
{token_rows or empty}</table></div>
<p class="muted">「許可を取り消す」は、Google アカウントの「サードパーティ製アプリとサービス」画面などで連携を解除する操作に相当します。</p></div>
<div class="card"><h2>発行したリフレッシュトークン</h2><div class="table-wrap"><table>
<tr><th>トークン</th><th>ユーザー</th><th>状態</th><th>有効期限</th></tr>
{refresh_rows or empty}</table></div></div>
<p class="muted">PKCE: {"有効" if self.settings.use_pkce else "無効 (--no-pkce)"}</p>"""
        return self.sessions.attach(html_page("auth", "認可サーバーの内部状態 (学習用)", body), session_id)
