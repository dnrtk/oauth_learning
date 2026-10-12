"""PKCE (Proof Key for Code Exchange, RFC 7636)。

認可コードが盗まれても、盗んだ人がトークンと交換できないようにする仕組みです。

  1. クライアントは毎回ランダムな「合言葉」(code_verifier) を作り、手元に隠しておく
  2. 合言葉のハッシュ値 (code_challenge) だけを認可リクエストに付けて送る
  3. トークンリクエストで合言葉そのもの (code_verifier) を送る
  4. 認可サーバーは「合言葉をハッシュしたら、最初に届いたハッシュ値と一致するか」を確かめる

ハッシュ値から元の合言葉を逆算することはできないため、認可リクエストや認可コードを
盗み見ただけの攻撃者は、正しい code_verifier を送ることができません。
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets

# RFC 7636 4.1: code_verifier は 43〜128 文字で、使える文字は A-Z a-z 0-9 - . _ ~
CODE_VERIFIER_PATTERN = re.compile(r"[A-Za-z0-9\-._~]{43,128}")


def generate_code_verifier() -> str:
    """推測できない code_verifier を生成する。"""
    # [演習 7-1] code_verifier を生成する
    # HINT: secrets.token_urlsafe(n) は n バイトの乱数を Base64URL 文字列にして返します。
    # HINT: 32 バイトなら 43 文字になり、RFC 7636 の要件 (43〜128 文字) を満たします。
    # HINT: random モジュールは予測可能なので、セキュリティ用途には使いません。
    return secrets.token_urlsafe(32)
    # [/演習 7-1]


def compute_code_challenge(code_verifier: str) -> str:
    """code_verifier から code_challenge を計算する (S256 方式)。"""
    # [演習 7-2] code_challenge を計算する (S256)
    # HINT: 計算式は BASE64URL(SHA256(code_verifier)) です。
    # HINT: hashlib.sha256(文字列.encode("ascii")).digest() で 32 バイトのハッシュ値が得られます。
    # HINT: base64.urlsafe_b64encode() の結果の末尾にある "=" (パディング) は取り除きます。
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    # [/演習 7-2]


def verify_pkce(code_verifier: str | None, code_challenge: str) -> bool:
    """トークンリクエストで届いた code_verifier が、保存していた code_challenge と対応するか確認する。"""
    # [演習 7-3] code_verifier を検証する
    # HINT: code_verifier が None、または CODE_VERIFIER_PATTERN.fullmatch() に合わなければ False。
    # HINT: compute_code_challenge(code_verifier) が code_challenge と一致すれば True。
    # HINT: 秘密の値の比較には == ではなく secrets.compare_digest() を使います (タイミング攻撃対策)。
    if code_verifier is None or CODE_VERIFIER_PATTERN.fullmatch(code_verifier) is None:
        return False
    expected = compute_code_challenge(code_verifier)
    return secrets.compare_digest(expected.encode("ascii"), code_challenge.encode("ascii"))
    # [/演習 7-3]
