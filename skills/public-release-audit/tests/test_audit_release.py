from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "audit_release.py"
)
PINNED_SHA = "d23441a48e516b6c34aea4fa41551a30e30af803"


def run(command: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"command failed: {command}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


class ReleaseAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        run(["git", "init", "-q"], self.repo)
        run(["git", "config", "user.name", "Release Audit Test"], self.repo)
        run(
            [
                "git",
                "config",
                "user.email",
                "123+release-audit@users.noreply.github.com",
            ],
            self.repo,
        )
        write(self.repo / "README.md", "# Fixture\n")
        write(self.repo / "LICENSE", "MIT\n")
        write(self.repo / ".gitignore", "*.tmp\n")
        write(
            self.repo / ".github" / "workflows" / "validate.yml",
            (
                "name: validate\n"
                "on: [push]\n"
                "permissions:\n"
                "  contents: read\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                f"      - uses: actions/checkout@{PINNED_SHA}\n"
            ),
        )
        run(["git", "add", "."], self.repo)
        run(["git", "commit", "-q", "-m", "initial"], self.repo)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def audit(self, mode: str) -> subprocess.CompletedProcess[str]:
        return run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.repo),
                "--mode",
                mode,
                "--format",
                "json",
            ],
            self.repo,
            check=False,
        )

    def test_clean_tree_is_go_and_read_only(self) -> None:
        before = run(["git", "status", "--porcelain=v1", "-z"], self.repo).stdout
        proc = self.audit("tree")
        after = run(["git", "status", "--porcelain=v1", "-z"], self.repo).stdout
        self.assertEqual(proc.returncode, 0, proc.stdout)
        report = json.loads(proc.stdout)
        self.assertEqual(report["summary"]["verdict"], "GO")
        self.assertEqual(before, after)

    def test_staged_secret_is_redacted_and_no_go(self) -> None:
        secret = "sk-" + "A" * 32
        write(self.repo / "config.txt", f"OPENAI_API_KEY={secret}\n")
        run(["git", "add", "config.txt"], self.repo)
        proc = self.audit("staged")
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn(secret, proc.stdout)
        report = json.loads(proc.stdout)
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("OPENAI_OR_XAI_KEY", codes)
        self.assertEqual(report["summary"]["verdict"], "NO-GO")

    def test_placeholder_is_not_a_secret(self) -> None:
        write(self.repo / "example.env", "API_KEY=your-api-key\n")
        run(["git", "add", "example.env"], self.repo)
        proc = self.audit("staged")
        report = json.loads(proc.stdout)
        codes = {item["code"] for item in report["findings"]}
        self.assertNotIn("GENERIC_SECRET_ASSIGNMENT", codes)

    def test_example_domain_url_credentials_are_fixture_data(self) -> None:
        write(
            self.repo / "fixture.txt",
            "reject https://user:pass@example.invalid/health\n",
        )
        run(["git", "add", "fixture.txt"], self.repo)
        proc = self.audit("staged")
        report = json.loads(proc.stdout)
        codes = {item["code"] for item in report["findings"]}
        self.assertNotIn("URL_EMBEDDED_CREDENTIAL", codes)

    def test_unpinned_action_requires_review(self) -> None:
        workflow = self.repo / ".github" / "workflows" / "validate.yml"
        text = workflow.read_text(encoding="utf-8").replace(
            PINNED_SHA, "v6"
        )
        write(workflow, text)
        run(["git", "add", str(workflow.relative_to(self.repo))], self.repo)
        proc = self.audit("staged")
        report = json.loads(proc.stdout)
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("UNPINNED_ACTION", codes)
        self.assertEqual(report["summary"]["verdict"], "REVIEW")

    def test_github_web_noreply_commit_email_is_safe(self) -> None:
        run(["git", "config", "user.email", "noreply@github.com"], self.repo)
        write(self.repo / "change.txt", "change\n")
        run(["git", "add", "change.txt"], self.repo)
        run(["git", "commit", "-q", "-m", "github web commit"], self.repo)
        proc = self.audit("history")
        report = json.loads(proc.stdout)
        codes = {item["code"] for item in report["findings"]}
        self.assertNotIn("COMMIT_EMAIL_EXPOSURE", codes)
        self.assertEqual(report["summary"]["verdict"], "GO")

    def test_non_noreply_commit_email_is_redacted_and_no_go(self) -> None:
        email = "alice" + "@" + "private.test"
        run(["git", "config", "user.email", email], self.repo)
        write(self.repo / "change.txt", "change\n")
        run(["git", "add", "change.txt"], self.repo)
        run(["git", "commit", "-q", "-m", "private author"], self.repo)
        proc = self.audit("history")
        self.assertNotIn(email, proc.stdout)
        report = json.loads(proc.stdout)
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("COMMIT_EMAIL_EXPOSURE", codes)
        self.assertEqual(report["summary"]["verdict"], "NO-GO")

    def test_deleted_historical_secret_is_detected_without_echo(self) -> None:
        secret = "ghp_" + "B" * 36
        write(self.repo / "old-secret.txt", secret + "\n")
        run(["git", "add", "old-secret.txt"], self.repo)
        run(["git", "commit", "-q", "-m", "add old value"], self.repo)
        run(["git", "rm", "-q", "old-secret.txt"], self.repo)
        run(["git", "commit", "-q", "-m", "remove old value"], self.repo)
        proc = self.audit("history")
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn(secret, proc.stdout)
        report = json.loads(proc.stdout)
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("GITHUB_TOKEN", codes)


if __name__ == "__main__":
    unittest.main()
