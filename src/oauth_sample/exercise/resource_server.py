# ============================================================================
# 演習用ファイルです。「TODO」と書かれた箇所を実装してください。
# 解答は src/oauth_sample/solution/ の同名ファイルにあります。
# ============================================================================
"""リソースサーバー (Resource Server)。

ユーザーのデータ (プロフィールやメモ) を持っている API サーバーです。
リクエストに付いているアクセストークンを確かめ、有効で、かつ必要なスコープを
持っている場合だけデータを返します。

エンドポイント:
  GET /api/profile   プロフィール (scope: profile が必要)
  GET /api/notes     メモ一覧 (scope: notes:read が必要)
  GET /              説明ページ
"""

from __future__ import annotations

from collections.abc import Callable

from .. import config
from ..common import (
    JsonDict,
    Request,
    Response,
    encode_basic_auth,
    html_page,
    http_request,
    json_response,
)
from ..config import Settings

# リソースサーバーが持っているユーザーデータ (本来はデータベース)
PROFILES: dict[str, JsonDict] = {
    "alice": {"username": "alice", "name": "Alice Liddell", "email": "alice@example.com"},
    "bob": {"username": "bob", "name": "Bob Builder", "email": "bob@example.com"},
}
NOTES: dict[str, list[JsonDict]] = {
    "alice": [
        {"id": 1, "title": "買い物", "body": "牛乳、卵、紅茶の葉"},
        {"id": 2, "title": "読書メモ", "body": "鏡の国のアリス を読み返す"},
    ],
    "bob": [
        {"id": 1, "title": "現場", "body": "月曜は資材の搬入"},
    ],
}


def extract_bearer_token(authorization: str | None) -> str | None:
    """Authorization ヘッダーからアクセストークンを取り出す (RFC 6750 2.1)。形式が違えば None。"""
    # [演習 6-2] Bearer トークンを取り出す
    # TODO: ここを実装してください
    # ヒント: ヘッダーの形式は "Bearer <トークン>" です。
    # ヒント: str.partition(" ") で「スキーム」と「残り」に分けられます。
    # ヒント: スキームの大文字小文字は区別しません ("bearer" も可)。トークンが空なら None。
    raise NotImplementedError("演習 6-2: Bearer トークンを取り出す")
    # [/演習 6-2]


def introspect_token(settings: Settings, token: str) -> JsonDict:
    """認可サーバーのイントロスペクションエンドポイントに、トークンが有効か問い合わせる。"""
    # [演習 6-3] 認可サーバーに問い合わせる
    # TODO: ここを実装してください
    # ヒント: common.http_request("resource", "POST", settings.introspection_endpoint, form=..., headers=...) を使います。
    # ヒント: form は {"token": token}
    # ヒント: リソースサーバー自身の認証として headers に
    # ヒント:   {"Authorization": encode_basic_auth(config.RESOURCE_SERVER_ID, config.RESOURCE_SERVER_SECRET)} を付けます。
    # ヒント: ステータスが 200 以外なら RuntimeError を送出し、200 なら result.body を返します。
    raise NotImplementedError("演習 6-3: 認可サーバーに問い合わせる")
    # [/演習 6-3]


def has_scope(token_info: JsonDict, required_scope: str) -> bool:
    """イントロスペクション結果のスコープに required_scope が含まれるか。"""
    # [演習 6-4] スコープを確認する
    # TODO: ここを実装してください
    # ヒント: token_info["scope"] はスペース区切りの文字列です (例: "profile notes:read")。
    # ヒント: 部分一致 ("notes" in "notes:read" は True になってしまう) ではなく、split() して要素で比較します。
    raise NotImplementedError("演習 6-4: スコープを確認する")
    # [/演習 6-4]


type _Loader = Callable[[str], JsonDict]


def _bearer_error(
    status: int, error: str | None, description: str, header_description: str, scope: str | None = None
) -> Response:
    """RFC 6750 3 に従い、WWW-Authenticate ヘッダー付きのエラーを返す。

    HTTP ヘッダーには ASCII しか入れられないため、ヘッダーには英語、JSON 本文には日本語の説明を入れる。
    """
    params = ['realm="oauth-sample"']
    if error is not None:
        params.append(f'error="{error}"')
        params.append(f'error_description="{header_description}"')
    if scope is not None:
        params.append(f'scope="{scope}"')
    body: JsonDict = {"error": error or "unauthorized", "error_description": description}
    return json_response(body, status=status, headers=[("WWW-Authenticate", "Bearer " + ", ".join(params))])


class ResourceServer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def handle(self, request: Request) -> Response:
        match (request.method, request.path):
            case ("GET", "/"):
                return self._index()
            case ("GET", "/api/profile"):
                return self._protected(request, "profile", lambda user: PROFILES.get(user, {}))
            case ("GET", "/api/notes"):
                return self._protected(request, "notes:read", lambda user: {"notes": NOTES.get(user, [])})
            case _:
                return json_response({"error": "not_found"}, status=404)

    def _protected(self, request: Request, required_scope: str, load: _Loader) -> Response:
        # ① トークンを取り出す。無ければ 401 (どうすればよいかを WWW-Authenticate で伝える)
        token = extract_bearer_token(request.header("Authorization"))
        if token is None:
            return _bearer_error(401, None, "アクセストークンが必要です", "Access token is required")
        # ② 認可サーバーに有効か問い合わせる。無効なら 401 invalid_token
        token_info = introspect_token(self.settings, token)
        if token_info.get("active") is not True:
            return _bearer_error(
                401, "invalid_token", "アクセストークンが無効または期限切れです", "The access token is invalid or expired"
            )
        # ③ この API に必要なスコープを持っているか。無ければ 403 insufficient_scope
        if not has_scope(token_info, required_scope):
            return _bearer_error(
                403,
                "insufficient_scope",
                "スコープが不足しています",
                "The access token does not have the required scope",
                scope=required_scope,
            )
        # ④ トークンの持ち主 (username) のデータだけを返す
        return json_response(load(str(token_info["username"])))

    def _index(self) -> Response:
        body = """
<div class="card">
<p>このサーバーは JSON API だけを提供します。ブラウザで直接
<a href="/api/profile"><code>/api/profile</code></a> を開くと、アクセストークンが無いので
<strong>401 Unauthorized</strong> が返るはずです。試してみてください。</p>
<ul>
<li><code>GET /api/profile</code> … 必要なスコープ <code>profile</code></li>
<li><code>GET /api/notes</code> … 必要なスコープ <code>notes:read</code></li>
</ul>
</div>"""
        return html_page("resource", "リソースサーバー (API)", body)
