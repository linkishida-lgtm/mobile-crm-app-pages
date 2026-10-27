#!/usr/bin/env python3
"""AIの指示・設定ファイルの変更を、内容を表示せず検出する。外部通信なし。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

BASELINE = ".agent-security-baseline.json"
SELF = "agent_security_check.py"
RULE_NAMES = {"agents.md", "agents.override.md", "claude.md", "claude.local.md", "skill.md", ".mcp.json", ".claude.json"}
GUARD_NAMES = {SELF, BASELINE, "AGENT_SECURITY.md", "test_agent_security_check.py"}


def protected(path):
    # 入れ子の指示書、設定、hooks、CIも監視する。大文字小文字の違いも拾う。
    parts = path.lower().split("/")
    return (parts[-1] in RULE_NAMES or path in GUARD_NAMES
            or any(p in {".claude", ".codex", ".github", ".vscode", ".agents"} for p in parts[:-1]))


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def inventory(root):
    # 未追跡の指示ファイルも対象。巨大な依存ディレクトリの中身は読まない。
    tracked = git("ls-files", "-z").decode("utf-8").split("\0")
    untracked = git("ls-files", "--others", "--exclude-standard", "-z").decode("utf-8").split("\0")
    ignored = git("ls-files", "--others", "--ignored", "--exclude-standard", "-z").decode("utf-8").split("\0")
    excluded = {"node_modules", ".git", ".venv", "venv", "vendor"}
    paths = set(tracked + untracked)
    paths.update(p for p in ignored if not (set(p.split("/")) & excluded))
    result = {}
    for p in sorted(paths):
        if not p or p == BASELINE or not protected(p):
            continue
        target = root / p
        # 外部を指すリンクから秘密情報を読まない。
        if target.is_symlink() or any(x.is_symlink() for x in target.parents if x != root.parent):
            raise ValueError("保護対象にシンボリックリンクがあります: " + p)
        if target.is_file():
            data = target.read_bytes()
            # Windowsの改行変換で誤検出せず、Gitの外部フィルターは実行しない。
            if b"\0" not in data:
                data = data.replace(b"\r\n", b"\n")
            result[p] = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-baseline", action="store_true", help="人間が差分を確認した後だけ基準を更新")
    parser.add_argument("--reviewed", action="store_true", help="差分を確認したことを明示")
    args = parser.parse_args()
    root = Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve()
    os.chdir(root)
    # Downloads配下やホームそのものを作業場所にしない。
    if root == Path.home().resolve() or any(p.name.lower() == "downloads" for p in (root, *root.parents)):
        raise ValueError("ホーム直下・Downloads配下では起動しないでください")
    current = inventory(root)
    path = root / BASELINE
    if path.is_symlink():
        raise ValueError("基準ファイルがシンボリックリンクです")
    if args.write_baseline:
        if not args.reviewed:
            raise ValueError("基準更新には --reviewed が必要です。AIが自動承認してはいけません")
        path.write_text(json.dumps({"version": 1, "files": current}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("基準を更新しました。差分と承認理由をPRに残してください。")
        return 0
    expected_doc = json.loads(path.read_text(encoding="utf-8"))
    if expected_doc.get("version") != 1 or not isinstance(expected_doc.get("files"), dict):
        raise ValueError("基準ファイルの形式が不正です")
    expected = expected_doc["files"]
    changed = sorted(p for p in set(current) | set(expected) if current.get(p) != expected.get(p))
    if changed:
        print("要確認: AIの指示・設定・CIファイルが基準と異なります。内容・秘密情報は表示しません。")
        for p in changed:
            status = "追加" if p not in expected else "削除" if p not in current else "変更"
            print(json.dumps({"status": status, "path": p}, ensure_ascii=False))
        print("自動修復・自動の基準更新はせず、差分を人間に確認してください。")
        return 1
    print(f"PASS: 保護対象 {len(current)} 件が基準と一致。PC全体の安全や内容の無害性を保証する結果ではありません。")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError):
        # エラーに認証情報やファイル本文が含まれる可能性があるため詳細は出さない。
        print("FAIL: 作業場所・Git・基準ファイル・リンクを確認してください。検査は完了していません。", file=sys.stderr)
        sys.exit(2)
