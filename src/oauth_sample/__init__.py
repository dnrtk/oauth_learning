"""OAuth 2.0 認可コードフローを自作して学ぶための教材。"""

from __future__ import annotations

import argparse
import time

from .config import Settings
from .runner import start_all, stop_all


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="oauth-sample",
        description="クライアント・認可サーバー・リソースサーバーを起動します。",
    )
    parser.add_argument(
        "implementation",
        choices=["exercise", "solution"],
        help="exercise = 自分で実装する演習版 / solution = 解答 (完成版)",
    )
    parser.add_argument(
        "--no-pkce",
        action="store_true",
        help="PKCE を使わずに動かす (演習 7 に取り組む前はこれを付けて起動します)",
    )
    args = parser.parse_args()

    settings = Settings(use_pkce=not args.no_pkce)
    servers = start_all(args.implementation, settings)
    print(
        f"""
==================================================================
 OAuth 2.0 学習用サーバーを起動しました ({args.implementation}, PKCE: {"有効" if settings.use_pkce else "無効"})

   クライアント       {settings.client_base_url}   ← ブラウザでここを開いてください
   認可サーバー       {settings.auth_base_url}
   リソースサーバー   {settings.resource_base_url}

 終了するには Ctrl+C を押してください。
==================================================================
""",
        flush=True,
    )
    try:
        while True:
            # Windows でも Ctrl+C を受け付けられるよう、短い間隔で待機する
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n停止しています...")
    finally:
        stop_all(servers)
