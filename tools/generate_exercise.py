"""解答版 (src/oauth_sample/solution) から演習版 (src/oauth_sample/exercise) を生成する教材メンテナンス用スクリプト。

解答版の中の

    # [演習 1-1] タイトル
    # HINT: ヒント
    ...解答コード...
    # [/演習 1-1]

というブロックを、ヒントと `raise NotImplementedError(...)` だけに置き換えます。

注意: 演習版に書き込んだ自分の解答は上書きされて消えます。そのため既に演習版がある場合は
--force を付けない限り実行しません。

    uv run python tools/generate_exercise.py [--force]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOLUTION_DIR = ROOT / "src" / "oauth_sample" / "solution"
EXERCISE_DIR = ROOT / "src" / "oauth_sample" / "exercise"

START = re.compile(r"^(?P<indent>\s*)# \[演習 (?P<id>[\d-]+)\] (?P<title>.+)$")
END = re.compile(r"^\s*# \[/演習 (?P<id>[\d-]+)\]$")
HINT = re.compile(r"^\s*# HINT: ?(?P<text>.*)$")

FILE_HEADER = (
    "# ============================================================================\n"
    "# 演習用ファイルです。「TODO」と書かれた箇所を実装してください。\n"
    "# 解答は src/oauth_sample/solution/ の同名ファイルにあります。\n"
    "# ============================================================================\n"
)


def transform(source: str, filename: str) -> str:
    output: list[str] = []
    current: re.Match[str] | None = None
    hints: list[str] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        if current is None:
            if (start := START.match(line)) is not None:
                current, hints = start, []
            output.append(line)
            continue
        if (end := END.match(line)) is not None:
            if end["id"] != current["id"]:
                sys.exit(f"{filename}:{lineno}: 演習 {current['id']} の終了マーカーが一致しません")
            indent = current["indent"]
            output.append(f"{indent}# TODO: ここを実装してください")
            output.extend(f"{indent}# ヒント: {h}" for h in hints)
            output.append(f'{indent}raise NotImplementedError("演習 {current["id"]}: {current["title"]}")')
            output.append(line)
            current = None
        elif (hint := HINT.match(line)) is not None:
            hints.append(hint["text"])
    if current is not None:
        sys.exit(f"{filename}: 演習 {current['id']} の終了マーカーがありません")
    return FILE_HEADER + "\n".join(output) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="既存の演習版を上書きする")
    args = parser.parse_args()

    if EXERCISE_DIR.exists() and not args.force:
        sys.exit(f"{EXERCISE_DIR} は既に存在します。上書きする場合は --force を付けてください (自分の解答は消えます)。")

    EXERCISE_DIR.mkdir(parents=True, exist_ok=True)
    (EXERCISE_DIR / "__init__.py").write_text(
        '"""演習版の実装。TODO を埋めて完成させてください。"""\n', encoding="utf-8"
    )
    for path in sorted(SOLUTION_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        (EXERCISE_DIR / path.name).write_text(
            transform(path.read_text(encoding="utf-8"), path.name), encoding="utf-8"
        )
        print(f"生成しました: {(EXERCISE_DIR / path.name).relative_to(ROOT)}")


if __name__ == "__main__":
    main()
