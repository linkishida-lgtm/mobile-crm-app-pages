"""危険な処理を使わず、変更検出と停止を一時Gitリポジトリで試験する。"""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

CHECKER = Path(__file__).with_name("agent_security_check.py").resolve()


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agent-guard-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        shutil.copyfile(CHECKER, self.root / CHECKER.name)
        (self.root / "AGENTS.md").write_text("# Rules\n", encoding="utf-8")
        (self.root / ".gitignore").write_text(".claude/\n", encoding="utf-8")
        subprocess.run(["git", "add", "AGENTS.md", ".gitignore", CHECKER.name], cwd=self.root, check=True)
        self.assertEqual(self.run_guard("--write-baseline", "--reviewed").returncode, 0)

    def run_guard(self, *args):
        return subprocess.run([sys.executable, "-I", str(CHECKER), *args], cwd=self.root, capture_output=True, text=True)

    def test_unchanged_and_normal_code(self):
        (self.root / "app.py").write_text("print('example')\n", encoding="utf-8")
        self.assertEqual(self.run_guard().returncode, 0)

    def test_modified_instruction_hides_contents(self):
        (self.root / "AGENTS.md").write_text("PRIVATE_TEST_MARKER", encoding="utf-8")
        result = self.run_guard()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("PRIVATE_TEST_MARKER", result.stdout + result.stderr)

    def test_deleted_instruction(self):
        (self.root / "AGENTS.md").unlink()
        self.assertEqual(self.run_guard().returncode, 1)

    def test_new_nested_override(self):
        folder = self.root / "sub"
        folder.mkdir()
        (folder / "AGENTS.override.md").write_text("example", encoding="utf-8")
        self.assertEqual(self.run_guard().returncode, 1)

    def test_ignored_config(self):
        folder = self.root / ".claude"
        folder.mkdir()
        (folder / "settings.local.json").write_text("{}", encoding="utf-8")
        self.assertEqual(self.run_guard().returncode, 1)

    def test_changed_checker(self):
        with (self.root / CHECKER.name).open("a", encoding="utf-8") as f:
            f.write("\n# changed\n")
        self.assertEqual(self.run_guard().returncode, 1)

    def test_crlf_is_not_a_change(self):
        (self.root / "AGENTS.md").write_bytes(b"# Rules\r\n")
        self.assertEqual(self.run_guard().returncode, 0)

    def test_symlink_is_rejected(self):
        target = self.root / "target.txt"
        target.write_text("PRIVATE_TEST_MARKER", encoding="utf-8")
        (self.root / "CLAUDE.md").symlink_to(target)
        self.assertEqual(self.run_guard().returncode, 2)

    def test_missing_baseline_is_failure(self):
        (self.root / ".agent-security-baseline.json").unlink()
        self.assertEqual(self.run_guard().returncode, 2)

    def test_unreviewed_rebaseline_is_rejected(self):
        self.assertEqual(self.run_guard("--write-baseline").returncode, 2)

    def test_downloads_is_rejected(self):
        folder = self.root / "Downloads" / "project"
        folder.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(folder)], check=True)
        result = subprocess.run([sys.executable, "-I", str(CHECKER), "--write-baseline", "--reviewed"], cwd=folder, capture_output=True)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
