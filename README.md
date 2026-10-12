# oauth-sample — 自作して学ぶ OAuth 2.0

OAuth 2.0 の **認可コードフロー (+ PKCE, リフレッシュトークン)** を、
クライアント・認可サーバー・リソースサーバーの 3 者すべて Python 標準ライブラリだけで実装しながら学ぶ教材です。

教材本文（解説と演習手順）は [docs/2026-10-10_OAuth入門-自作して学ぶ認可コードフロー.html](docs/2026-10-10_OAuth入門-自作して学ぶ認可コードフロー.html) をブラウザで開いてください。

## クイックスタート

```bash
uv sync

# 完成版を動かしてみる → ブラウザで http://127.0.0.1:8000 を開く
uv run oauth-sample solution

# 演習版を動かす (演習 7 の PKCE に取り組むまでは --no-pkce を付ける)
uv run oauth-sample exercise --no-pkce

# 演習の答え合わせ
uv run pytest -k step1             # 演習 1 だけ
uv run pytest                      # 演習版すべて
uv run pytest --impl solution      # 解答版 (すべて通る)
```

## 構成

| パス | 内容 |
| --- | --- |
| `src/oauth_sample/exercise/` | **演習版**。`TODO` を埋めて完成させる |
| `src/oauth_sample/solution/` | 解答 (完成版) |
| `src/oauth_sample/common.py` | HTTP サーバー・ログ・セッションなどの下回り (演習対象外) |
| `src/oauth_sample/config.py` | ポート番号、クライアント登録情報、ユーザー、有効期限 |
| `tests/` | 演習ごとのテスト (`test_stepN.py`) と通しテスト (`test_e2e.py`) |
| `tools/generate_exercise.py` | 解答版から演習版を再生成する教材メンテナンス用スクリプト |

| サーバー | URL |
| --- | --- |
| クライアント (メモ閲覧アプリ) | http://127.0.0.1:8000 |
| 認可サーバー | http://127.0.0.1:9000 |
| リソースサーバー (API) | http://127.0.0.1:9100 |

デモ用アカウント: `alice` / `alice-pass`、`bob` / `bob-pass`

> [!WARNING]
> 学習用の実装です。HTTP (非 TLS)、メモリ上の保存、平文パスワード、トークンのログ出力など、
> 本番では許されない簡略化をしています。実サービスでは実績のあるライブラリ / IDaaS を使ってください。

演習版を最初の状態に戻したい場合は `uv run python tools/generate_exercise.py --force` を実行します (自分の解答は消えます)。
