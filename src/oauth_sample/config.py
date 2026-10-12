"""教材全体で共有する設定値。

実際のサービスでは、クライアントの登録情報は認可サーバーのデータベースに保存され、
クライアント側は自分の client_secret を環境変数やシークレットストアから読み込みます。
ここでは学習しやすいように 1 ファイルにまとめています。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """3 つのサーバーの待ち受けアドレスと動作モード。"""

    # "localhost" だと Windows で IPv6 → IPv4 のフォールバックに時間がかかることがあるため、
    # ループバックアドレスを直接指定しています。
    host: str = "127.0.0.1"
    client_port: int = 8000
    auth_port: int = 9000
    resource_port: int = 9100
    use_pkce: bool = True

    @property
    def client_base_url(self) -> str:
        return f"http://{self.host}:{self.client_port}"

    @property
    def auth_base_url(self) -> str:
        return f"http://{self.host}:{self.auth_port}"

    @property
    def resource_base_url(self) -> str:
        return f"http://{self.host}:{self.resource_port}"

    @property
    def redirect_uri(self) -> str:
        """認可サーバーが認可コードを返す先 (クライアントのコールバック URL)。"""
        return f"{self.client_base_url}/callback"

    @property
    def authorization_endpoint(self) -> str:
        return f"{self.auth_base_url}/authorize"

    @property
    def token_endpoint(self) -> str:
        return f"{self.auth_base_url}/token"

    @property
    def introspection_endpoint(self) -> str:
        return f"{self.auth_base_url}/introspect"


# ---------------------------------------------------------------------------
# クライアント (第三者アプリ) の登録情報
# ---------------------------------------------------------------------------
CLIENT_ID = "demo-client"
CLIENT_SECRET = "demo-client-secret"
CLIENT_NAME = "メモ閲覧アプリ (デモ)"
# クライアントが要求するスコープ (スペース区切り)
CLIENT_SCOPE = "profile notes:read"

# ---------------------------------------------------------------------------
# リソースサーバーが認可サーバーに問い合わせるときの認証情報
# ---------------------------------------------------------------------------
RESOURCE_SERVER_ID = "demo-resource-server"
RESOURCE_SERVER_SECRET = "demo-resource-server-secret"

# ---------------------------------------------------------------------------
# 認可サーバーに登録されているユーザー (リソースオーナー)
# 本物のサービスではパスワードはハッシュ化して保存します。
# ---------------------------------------------------------------------------
USERS: dict[str, str] = {
    "alice": "alice-pass",
    "bob": "bob-pass",
}

# 認可サーバーが知っているスコープと、同意画面に表示する説明
SCOPE_DESCRIPTIONS: dict[str, str] = {
    "profile": "あなたのプロフィール (名前・メールアドレス) を読み取る",
    "notes:read": "あなたのメモを読み取る",
}

# ---------------------------------------------------------------------------
# 有効期限 (秒)。動きを観察しやすいようにアクセストークンは短めにしています。
# ---------------------------------------------------------------------------
AUTHORIZATION_CODE_TTL_SECONDS = 60
ACCESS_TOKEN_TTL_SECONDS = 120
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24


@dataclass(frozen=True)
class ClientRegistration:
    """認可サーバーが保持しているクライアントの登録情報。"""

    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: tuple[str, ...]
    allowed_scopes: frozenset[str]


def registered_clients(settings: Settings) -> dict[str, ClientRegistration]:
    """認可サーバーに事前登録されているクライアントの一覧を返す。"""
    client = ClientRegistration(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        client_name=CLIENT_NAME,
        redirect_uris=(settings.redirect_uri,),
        allowed_scopes=frozenset(SCOPE_DESCRIPTIONS),
    )
    return {client.client_id: client}
