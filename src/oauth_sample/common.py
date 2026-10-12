"""HTTP まわりの下回り (OAuth とは直接関係しない部分)。

OAuth の仕組みそのものに集中できるよう、Web フレームワークを使わずに
標準ライブラリだけで「リクエストを受けてレスポンスを返す」最小限の仕組みを用意しています。
演習でこのファイルを編集する必要はありません。
"""

from __future__ import annotations

import base64
import html
import json
import os
import secrets
import sys
import threading
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Literal

type JsonDict = dict[str, Any]
type AppName = Literal["client", "auth", "resource"]

APP_LABELS: dict[AppName, str] = {
    "client": "クライアント",
    "auth": "認可サーバー",
    "resource": "リソースサーバー",
}


# ===========================================================================
# OAuth のエラー
# ===========================================================================
class OAuthError(Exception):
    """OAuth 仕様で定められたエラー応答 (RFC 6749 4.1.2.1 / 5.2) を表す例外。

    error には仕様で決められたエラーコード (invalid_request, invalid_grant など) を入れ、
    description には人間向けの説明を入れます。
    """

    def __init__(self, error: str, description: str = "", status: int = 400) -> None:
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error
        self.description = description
        self.status = status

    def to_json(self) -> JsonDict:
        body: JsonDict = {"error": self.error}
        if self.description:
            body["error_description"] = self.description
        return body


# ===========================================================================
# ログ出力 (どのサーバーが何を送受信したかを色分けして表示する)
# ===========================================================================
_COLORS: dict[AppName, str] = {"client": "36", "auth": "33", "resource": "35"}
_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
_log_lock = threading.Lock()
# ログに出すと危ないフォーム項目 (学習用にトークンは表示するが、パスワードは隠す)
_MASKED_FIELDS = frozenset({"password"})


def log(app: AppName, message: str) -> None:
    label = f"[{APP_LABELS[app]}]"
    if _USE_COLOR:
        label = f"\033[{_COLORS[app]}m{label}\033[0m"
    with _log_lock:
        for line in message.splitlines() or [""]:
            print(f"{label} {line}", flush=True)


def _format_params(title: str, params: dict[str, str]) -> list[str]:
    lines = []
    for key, value in params.items():
        shown = "********" if key in _MASKED_FIELDS else value
        lines.append(f"      {title} {key} = {shown}")
    return lines


# ===========================================================================
# リクエスト / レスポンス
# ===========================================================================
@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    form: dict[str, str]
    headers: dict[str, str]  # キーは小文字
    cookies: dict[str, str]

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: list[tuple[str, str]] = field(default_factory=list)

    def set_cookie(self, name: str, value: str, *, max_age: int | None = None) -> None:
        # HttpOnly: JavaScript から読めない / SameSite=Lax: 他サイトからの POST では送られない
        parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        self.headers.append(("Set-Cookie", "; ".join(parts)))


type Handler = Callable[[Request], Response]


def redirect(location: str) -> Response:
    """302 Found でブラウザを別の URL へ移動させる。OAuth のフロントチャネルの正体はこれです。"""
    return Response(status=302, headers=[("Location", location)])


def json_response(
    data: JsonDict, status: int = 200, headers: list[tuple[str, str]] | None = None
) -> Response:
    # トークンを含む応答はキャッシュさせてはいけない (RFC 6749 5.1)
    all_headers = [("Cache-Control", "no-store"), ("Pragma", "no-cache"), *(headers or [])]
    body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    return Response(
        status=status,
        body=body,
        content_type="application/json; charset=utf-8",
        headers=all_headers,
    )


def add_query_params(url: str, params: dict[str, str]) -> str:
    """URL の末尾にクエリパラメータを追加する (既存のクエリがあれば & でつなぐ)。"""
    separator = "&" if urllib.parse.urlsplit(url).query else "?"
    return url + separator + urllib.parse.urlencode(params)


# ===========================================================================
# HTML
# ===========================================================================
def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def pretty_json(data: object) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - {app_label}</title>
<style>
:root {{
  --bg: #f7f7f8; --fg: #1d1d1f; --card: #ffffff; --muted: #6b6b73; --border: #d9d9de;
  --client: #1f6feb; --auth: #c26a00; --resource: #8a3ffc;
  --ok: #1a7f37; --ng: #cf222e; --code-bg: #f0f0f3;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #16161a; --fg: #e8e8ec; --card: #202026; --muted: #a0a0aa; --border: #3a3a42;
    --client: #58a6ff; --auth: #f0a040; --resource: #b48cff;
    --ok: #3fb950; --ng: #ff6b6b; --code-bg: #2a2a31;
  }}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Hiragino Sans", "Yu Gothic", sans-serif;
  font-size: 1rem; line-height: 1.7; }}
.banner {{ padding: .6rem 1rem; color: #fff; background: var(--{app}); font-weight: bold; }}
.banner small {{ font-weight: normal; opacity: .9; margin-left: .5rem; }}
main {{ max-width: 52rem; margin: 0 auto; padding: 1rem; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
  padding: 1rem 1.25rem; margin: 1rem 0; }}
h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.15rem; margin-top: 0; }}
code, pre {{ font-family: "SF Mono", Menlo, Consolas, "Yu Gothic", monospace; font-size: .875rem; }}
code {{ background: var(--code-bg); padding: .1em .3em; border-radius: 4px; word-break: break-all; }}
pre {{ background: var(--code-bg); padding: .75rem; border-radius: 6px; overflow-x: auto; }}
.muted {{ color: var(--muted); font-size: .9rem; }}
.success {{ border-left: 4px solid var(--ok); }}
.success::before {{ content: "✔ 成功"; color: var(--ok); font-weight: bold; display: block; }}
.error {{ border-left: 4px solid var(--ng); }}
.error::before {{ content: "✖ エラー"; color: var(--ng); font-weight: bold; display: block; }}
.note {{ border-left: 4px solid var(--muted); }}
.note::before {{ content: "ℹ 学習メモ"; color: var(--muted); font-weight: bold; display: block; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid var(--border); padding: .35rem .5rem; text-align: left; vertical-align: top; }}
.table-wrap {{ overflow-x: auto; }}
button, .button {{ display: inline-block; font: inherit; padding: .45rem 1rem; margin: .25rem .25rem .25rem 0;
  border-radius: 6px; border: 1px solid var(--{app}); background: var(--{app}); color: #fff;
  cursor: pointer; text-decoration: none; }}
button.secondary, .button.secondary {{ background: transparent; color: var(--{app}); }}
form.inline {{ display: inline; }}
label {{ display: block; margin: .5rem 0; }}
input[type=text], input[type=password] {{ font: inherit; padding: .35rem .5rem; width: 100%;
  max-width: 20rem; border: 1px solid var(--border); border-radius: 6px; background: var(--bg); color: var(--fg); }}
</style>
</head>
<body>
<div class="banner">{app_label}<small>{base}</small></div>
<main>
<h1>{title}</h1>
{body}
</main>
</body>
</html>
"""

_APP_BASES: dict[AppName, str] = {}


def html_page(app: AppName, title: str, body: str, status: int = 200) -> Response:
    """各サーバー共通の見た目で HTML ページを返す。上部の色帯で「いまどのサーバーにいるか」が分かる。"""
    page = _PAGE_TEMPLATE.format(
        title=esc(title),
        app=app,
        app_label=esc(APP_LABELS[app]),
        base=esc(_APP_BASES.get(app, "")),
        body=body,
    )
    return Response(status=status, body=page.encode("utf-8"))


# ===========================================================================
# セッション (Cookie にランダムな ID だけを入れ、中身はサーバー側のメモリに置く)
# ===========================================================================
class SessionStore[T]:
    def __init__(self, cookie_name: str, factory: Callable[[], T]) -> None:
        self.cookie_name = cookie_name
        self._factory = factory
        self._data: dict[str, T] = {}
        self._lock = threading.Lock()

    def load(self, request: Request) -> tuple[str, T]:
        """Cookie からセッションを取り出す。無ければ新しく作る。"""
        session_id = request.cookies.get(self.cookie_name)
        with self._lock:
            if session_id is not None and session_id in self._data:
                return session_id, self._data[session_id]
            session_id = secrets.token_urlsafe(32)
            session = self._factory()
            self._data[session_id] = session
            return session_id, session

    def attach(self, response: Response, session_id: str) -> Response:
        response.set_cookie(self.cookie_name, session_id)
        return response


# ===========================================================================
# HTTP Basic 認証ヘッダー (クライアント認証に使う)
# ===========================================================================
def encode_basic_auth(username: str, password: str) -> str:
    """Authorization: Basic ... の値を作る。

    RFC 6749 2.3.1 により、client_id / client_secret は URL エンコードしてから
    "id:secret" の形にして Base64 化します。
    """
    raw = f"{urllib.parse.quote(username, safe='')}:{urllib.parse.quote(password, safe='')}"
    return "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")


def decode_basic_auth(header_value: str | None) -> tuple[str, str] | None:
    """Authorization: Basic ... を (username, password) に戻す。形式が不正なら None。"""
    if header_value is None:
        return None
    scheme, _, encoded = header_value.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except ValueError:
        return None
    username, sep, password = decoded.partition(":")
    if not sep:
        return None
    return urllib.parse.unquote(username), urllib.parse.unquote(password)


# ===========================================================================
# バックチャネル通信 (サーバー同士がブラウザを介さず直接 HTTP でやりとりする)
# ===========================================================================
@dataclass
class HttpResult:
    status: int
    body: JsonDict
    headers: dict[str, str]


# 社内プロキシの環境変数が設定されていてもローカル通信がプロキシに流れないようにする
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_request(
    app: AppName,
    method: str,
    url: str,
    *,
    form: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> HttpResult:
    """JSON を返す API を呼び出す。送受信内容はログに出力される。"""
    data = urllib.parse.urlencode(form).encode("utf-8") if form is not None else None
    all_headers = dict(headers or {})
    if data is not None:
        all_headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method, headers=all_headers)

    lines = [f"→ {method} {url}   ※バックチャネル (ブラウザを経由しない直接通信)"]
    for name, value in all_headers.items():
        if name.lower() == "authorization":
            lines.append(f"      header Authorization: {value}")
    lines += _format_params("form", form or {})
    log(app, "\n".join(lines))

    try:
        with _opener.open(req, timeout=10) as resp:
            status = resp.status
            raw = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as err:
        status = err.code
        raw = err.read()
        resp_headers = {k.lower(): v for k, v in err.headers.items()}

    try:
        body: JsonDict = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        body = {"raw": raw.decode("utf-8", errors="replace")}
    log(app, f"← {status} {json.dumps(body, ensure_ascii=False)}")
    return HttpResult(status=status, body=body, headers=resp_headers)


# ===========================================================================
# HTTP サーバー
# ===========================================================================
def _first_values(parsed: dict[str, list[str]]) -> dict[str, str]:
    # OAuth ではパラメータの重複は許されない (RFC 6749 3.1)。ここでは簡単のため先頭の値を使う。
    return {key: values[0] for key, values in parsed.items()}


def _parse_cookies(header_value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in header_value.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name:
            cookies[name] = value
    return cookies


def _log_incoming(app: AppName, request: Request) -> None:
    lines = [f"← {request.method} {request.path}"]
    lines += _format_params("query", request.query)
    lines += _format_params("form ", request.form)
    authorization = request.header("Authorization")
    if authorization is not None:
        lines.append(f"      header Authorization: {authorization}")
    log(app, "\n".join(lines))


def _log_outgoing(app: AppName, response: Response) -> None:
    message = f"→ {response.status}"
    location = next((v for k, v in response.headers if k == "Location"), None)
    if location is not None:
        message += f" Location: {location}   ※ブラウザにリダイレクトを指示"
    elif response.content_type.startswith("application/json"):
        message += " " + json.dumps(json.loads(response.body), ensure_ascii=False)
    else:
        message += " (HTML)"
    log(app, message)


def start_server(
    app: AppName, host: str, port: int, handler: Handler
) -> ThreadingHTTPServer:
    """別スレッドで HTTP サーバーを起動して返す。"""

    class _RequestHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def log_message(self, format: str, *args: Any) -> None:
            # 標準のアクセスログは使わず、_log_incoming / _log_outgoing で出力する
            return

        def _handle(self) -> None:
            split = urllib.parse.urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length) if length > 0 else b""
            form: dict[str, str] = {}
            if self.headers.get_content_type() == "application/x-www-form-urlencoded":
                form = _first_values(
                    urllib.parse.parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
                )
            request = Request(
                method=self.command,
                path=split.path,
                query=_first_values(urllib.parse.parse_qs(split.query, keep_blank_values=True)),
                form=form,
                headers={k.lower(): v for k, v in self.headers.items()},
                cookies=_parse_cookies(self.headers.get("Cookie", "")),
            )
            quiet = request.path == "/favicon.ico"
            if not quiet:
                _log_incoming(app, request)

            try:
                response = handler(request)
            except NotImplementedError as exc:
                log(app, f"  ⚠ 未実装の演習に到達しました: {exc}")
                response = html_page(
                    app,
                    "未実装の演習があります",
                    f'<div class="card error"><p>この処理はまだ実装されていません。</p>'
                    f"<p><code>{esc(exc)}</code></p>"
                    f'<p class="muted">該当する関数を実装してから、サーバーを再起動してください。</p></div>',
                    status=501,
                )
            except Exception:
                traceback.print_exc()
                response = html_page(
                    app,
                    "サーバーエラー",
                    '<div class="card error"><p>予期しないエラーが発生しました。ターミナルのログを確認してください。</p></div>',
                    status=500,
                )

            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            for name, value in response.headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.body)
            if not quiet:
                _log_outgoing(app, response)

    _APP_BASES[app] = f"http://{host}:{port}"
    server = ThreadingHTTPServer((host, port), _RequestHandler)
    thread = threading.Thread(target=server.serve_forever, name=f"{app}-server", daemon=True)
    thread.start()
    return server
