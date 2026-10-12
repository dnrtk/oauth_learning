"""演習 7: PKCE。"""

from __future__ import annotations

import pytest

from oauth_sample.common import OAuthError

from .conftest import Impl


def test_step7_1_generate_code_verifier(impl: Impl) -> None:
    verifiers = {impl.pkce.generate_code_verifier() for _ in range(20)}
    assert len(verifiers) == 20, "毎回違う値でなければなりません"
    for verifier in verifiers:
        assert impl.pkce.CODE_VERIFIER_PATTERN.fullmatch(verifier), "43〜128 文字、A-Z a-z 0-9 - . _ ~ のみ"


def test_step7_2_compute_code_challenge_rfc_example(impl: Impl) -> None:
    # RFC 7636 Appendix B に載っている例そのもの
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert impl.pkce.compute_code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_step7_3_verify_pkce(impl: Impl) -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert impl.pkce.verify_pkce(verifier, challenge) is True
    assert impl.pkce.verify_pkce(None, challenge) is False
    assert impl.pkce.verify_pkce(verifier[:-1] + "Y", challenge) is False
    assert impl.pkce.verify_pkce("short", impl.pkce.compute_code_challenge("short")) is False, (
        "43 文字未満の code_verifier は形式エラーとして拒否します"
    )
    # code_verifier ではなく code_challenge をそのまま送ってきても通らないこと
    assert impl.pkce.verify_pkce(challenge, challenge) is False


def test_step7_4_extract_pkce_challenge(impl: Impl) -> None:
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    query = {"code_challenge": challenge, "code_challenge_method": "S256"}
    assert impl.auth_server.extract_pkce_challenge(query) == challenge


@pytest.mark.parametrize(
    "query",
    [
        {},
        {"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},  # method 省略 = plain
        {"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "plain"},
        {"code_challenge": "too-short", "code_challenge_method": "S256"},
    ],
)
def test_step7_4_extract_pkce_challenge_invalid(impl: Impl, query: dict[str, str]) -> None:
    with pytest.raises(OAuthError) as info:
        impl.auth_server.extract_pkce_challenge(query)
    assert info.value.error == "invalid_request"
