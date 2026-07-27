#!/usr/bin/env python3
"""Read-only, redacting pre-publication audit for Git repositories."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
SEVERITY_RANK = {"info": 0, "warning": 1, "high": 2, "critical": 3}

SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "PRIVATE_KEY",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "GITHUB_TOKEN",
        "critical",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    ),
    (
        "OPENAI_OR_XAI_KEY",
        "critical",
        re.compile(r"\b(?:sk|xai)-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "AWS_ACCESS_KEY",
        "critical",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "GOOGLE_API_KEY",
        "critical",
        re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    ),
    (
        "SLACK_TOKEN",
        "critical",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ),
    (
        "JWT",
        "high",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    (
        "DISCORD_WEBHOOK",
        "critical",
        re.compile(
            r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/"
            r"\d{10,}/[A-Za-z0-9._-]{20,}"
        ),
    ),
)

GENERIC_SECRET = re.compile(
    r"""(?ix)
    \b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|
       secret|password|passwd)\b
    \s*[:=]\s*
    ["']?([^\s"'#,;]{12,})
    """
)
PLACEHOLDER = re.compile(
    r"(?i)(your|example|dummy|sample|test|changeme|replace|placeholder|"
    r"redacted|xxxxx|token|secret|password|api.?key|none|unset|null|"
    r"optional|os\.getenv|process\.env|\$\{|\{\{|<|>)"
)
EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
IPV4_PATTERN = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
URL_PATTERN = re.compile(r"""(?i)\bhttps?://[^\s"'<>]+""")
CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

SAFE_EMAIL_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
    "example.invalid",
    "users.noreply.github.com",
    "localhost",
}
SAFE_EMAIL_ADDRESSES = {"noreply@github.com"}
SENSITIVE_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "service-account.json",
    "auth.json",
}
SENSITIVE_SUFFIXES = {".pem", ".p12", ".pfx", ".key", ".keystore"}
LOCAL_ARTIFACT_PARTS = {
    ".ccg",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    "node_modules",
}
LOCAL_ARTIFACT_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
ARCHIVE_OR_EXECUTABLE_SUFFIXES = {
    ".7z",
    ".apk",
    ".appx",
    ".bat",
    ".bin",
    ".cmd",
    ".dll",
    ".dmg",
    ".exe",
    ".ipa",
    ".jar",
    ".msi",
    ".ps1",
    ".rar",
    ".so",
    ".tar",
    ".tgz",
    ".war",
    ".zip",
}


def _safe_text(value: str, limit: int = 240) -> str:
    value = CONTROL_PATTERN.sub("?", value)
    for _, _, pattern in SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    if len(value) > limit:
        value = value[: limit - 3] + "..."
    return value


def _safe_path(value: str) -> str:
    return _safe_text(value.replace("\\", "/"), 320)


class Audit:
    def __init__(
        self,
        root: Path,
        *,
        mode: str,
        max_file_bytes: int,
        max_history_blobs: int,
    ) -> None:
        self.root = root
        self.mode = mode
        self.max_file_bytes = max_file_bytes
        self.max_history_blobs = max_history_blobs
        self.findings: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []
        self.skipped: list[dict[str, str]] = []
        self.candidates = 0
        self._finding_keys: set[tuple[str, str, int | None, str]] = set()

    def git(
        self,
        *args: str,
        input_bytes: bytes | None = None,
        timeout: int = 30,
        check: bool = True,
    ) -> bytes:
        command = ["git", *args]
        try:
            proc = subprocess.run(
                command,
                cwd=self.root,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"git command failed: {args[0]}: {exc.__class__.__name__}") from exc
        if check and proc.returncode != 0:
            message = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            detail = message[-1] if message else f"exit {proc.returncode}"
            raise RuntimeError(f"git {args[0]} failed: {_safe_text(detail)}")
        return proc.stdout

    def add_finding(
        self,
        code: str,
        severity: str,
        path: str,
        message: str,
        *,
        line: int | None = None,
        source: str = "tree",
    ) -> None:
        safe_path = _safe_path(path)
        key = (code, safe_path, line, source)
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        self.findings.append(
            {
                "code": code,
                "severity": severity,
                "path": safe_path,
                "line": line,
                "source": source,
                "message": _safe_text(message),
            }
        )

    def add_error(self, stage: str, message: str) -> None:
        self.errors.append({"stage": _safe_text(stage), "message": _safe_text(message)})

    def add_skip(self, path: str, reason: str, source: str) -> None:
        self.skipped.append(
            {"path": _safe_path(path), "reason": _safe_text(reason), "source": source}
        )

    @staticmethod
    def _line(text: str, offset: int) -> int:
        return text.count("\n", 0, offset) + 1

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        if PLACEHOLDER.search(value):
            return True
        if any(ch in value for ch in "[]()"):
            return True
        if value.lower() in {"true", "false", "string", "str", "bytes"}:
            return True
        return False

    @staticmethod
    def _is_safe_email(email: str) -> bool:
        normalized = email.strip().lower()
        domain = normalized.rsplit("@", 1)[-1]
        return (
            normalized in SAFE_EMAIL_ADDRESSES
            or domain in SAFE_EMAIL_DOMAINS
            or domain.endswith(".example")
        )

    def scan_text(self, path: str, text: str, source: str) -> None:
        for code, severity, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                self.add_finding(
                    code,
                    severity,
                    path,
                    "Potential credential material detected; matched value is redacted.",
                    line=self._line(text, match.start()),
                    source=source,
                )

        for match in GENERIC_SECRET.finditer(text):
            value = match.group(2)
            if self._is_placeholder(value):
                continue
            self.add_finding(
                "GENERIC_SECRET_ASSIGNMENT",
                "high",
                path,
                "Non-placeholder secret-like assignment detected; value is redacted.",
                line=self._line(text, match.start()),
                source=source,
            )

        for match in EMAIL_PATTERN.finditer(text):
            email = match.group(0)
            if self._is_safe_email(email):
                continue
            self.add_finding(
                "PERSONAL_EMAIL",
                "warning",
                path,
                "Non-example email address detected; address is redacted.",
                line=self._line(text, match.start()),
                source=source,
            )

        for match in IPV4_PATTERN.finditer(text):
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if not address.is_global:
                continue
            self.add_finding(
                "PUBLIC_IP_ADDRESS",
                "warning",
                path,
                "Public IPv4 address detected; address is redacted.",
                line=self._line(text, match.start()),
                source=source,
            )

        for match in URL_PATTERN.finditer(text):
            value = match.group(0).rstrip(".,);]")
            try:
                parsed = urlsplit(value)
            except ValueError:
                continue
            hostname = (parsed.hostname or "").lower()
            username = parsed.username or ""
            password = parsed.password or ""
            fixture_credentials = (
                hostname in SAFE_EMAIL_DOMAINS
                and username.lower() in {"user", "username", "test", "example"}
                and password.lower() in {"", "pass", "password", "test", "example"}
            )
            if (username or password) and not fixture_credentials:
                self.add_finding(
                    "URL_EMBEDDED_CREDENTIAL",
                    "critical",
                    path,
                    "URL with embedded user information detected; URL is redacted.",
                    line=self._line(text, match.start()),
                    source=source,
                )
            if hostname in {"localhost"} or hostname.endswith(
                (".local", ".internal", ".lan", ".corp")
            ):
                self.add_finding(
                    "PRIVATE_HOSTNAME",
                    "warning",
                    path,
                    "Local or private hostname detected; hostname is redacted.",
                    line=self._line(text, match.start()),
                    source=source,
                )

        if path.lower().startswith(".github/workflows/") and path.lower().endswith(
            (".yml", ".yaml")
        ):
            self.scan_workflow(path, text, source)

    def scan_workflow(self, path: str, text: str, source: str) -> None:
        permissions_seen = False
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("permissions:"):
                permissions_seen = True
            if re.match(r"permissions:\s*write-all\b", stripped, re.I):
                self.add_finding(
                    "WORKFLOW_WRITE_ALL",
                    "high",
                    path,
                    "Workflow grants write-all permissions.",
                    line=number,
                    source=source,
                )
            if re.match(
                r"(contents|actions|checks|deployments|id-token|issues|packages|"
                r"pages|pull-requests|repository-projects|security-events|statuses):\s*write\b",
                stripped,
                re.I,
            ):
                self.add_finding(
                    "WORKFLOW_WRITE_PERMISSION",
                    "warning",
                    path,
                    "Workflow write permission requires explicit review.",
                    line=number,
                    source=source,
                )
            if re.match(r"persist-credentials:\s*true\b", stripped, re.I):
                self.add_finding(
                    "WORKFLOW_PERSISTS_CREDENTIALS",
                    "high",
                    path,
                    "Checkout credentials are explicitly persisted.",
                    line=number,
                    source=source,
                )
            uses = re.search(r"\buses:\s*([^\s#]+)", stripped)
            if uses:
                ref = uses.group(1)
                if ref.startswith(("./", "docker://")):
                    continue
                if "@" not in ref:
                    self.add_finding(
                        "ACTION_WITHOUT_REF",
                        "high",
                        path,
                        "Third-party Action has no explicit ref.",
                        line=number,
                        source=source,
                    )
                    continue
                revision = ref.rsplit("@", 1)[-1]
                if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
                    self.add_finding(
                        "UNPINNED_ACTION",
                        "warning",
                        path,
                        "Third-party Action is not pinned to a full commit SHA.",
                        line=number,
                        source=source,
                    )
        if not permissions_seen:
            self.add_finding(
                "WORKFLOW_PERMISSIONS_IMPLICIT",
                "warning",
                path,
                "Workflow does not declare an explicit permissions block.",
                source=source,
            )

    @staticmethod
    def _is_binary(data: bytes) -> bool:
        if b"\x00" in data[:8192]:
            return True
        if not data:
            return False
        sample = data[:8192]
        controls = sum(byte < 9 or (13 < byte < 32) for byte in sample)
        return controls / len(sample) > 0.05

    def scan_blob(
        self,
        path: str,
        data: bytes,
        *,
        source: str,
        symlink: bool = False,
    ) -> None:
        self.candidates += 1
        normalized = path.replace("\\", "/")
        parts = tuple(part for part in normalized.split("/") if part)
        name = parts[-1] if parts else normalized
        lower_name = name.lower()
        suffix = Path(name).suffix.lower()

        if (
            lower_name in SENSITIVE_NAMES
            or (lower_name.startswith(".env.") and lower_name not in {".env.example", ".env.sample"})
            or suffix in SENSITIVE_SUFFIXES
        ):
            self.add_finding(
                "SENSITIVE_FILENAME",
                "high",
                normalized,
                "Sensitive filename is included in the release scope.",
                source=source,
            )
        if any(part in LOCAL_ARTIFACT_PARTS for part in parts) or name in LOCAL_ARTIFACT_NAMES:
            self.add_finding(
                "LOCAL_ARTIFACT",
                "warning",
                normalized,
                "Local development artifact is included in the release scope.",
                source=source,
            )
        if lower_name.endswith((".log", ".tmp", ".bak", ".swp")):
            self.add_finding(
                "TEMPORARY_FILE",
                "warning",
                normalized,
                "Temporary, log, or backup file is included in the release scope.",
                source=source,
            )
        if symlink:
            self.add_finding(
                "SYMLINK",
                "high",
                normalized,
                "Symlink is included; target is intentionally not displayed.",
                source=source,
            )
        if len(data) > self.max_file_bytes:
            self.add_skip(normalized, "file exceeds max scan size", source)
            self.add_finding(
                "LARGE_FILE",
                "warning",
                normalized,
                "File exceeds the configured content scan limit.",
                source=source,
            )
            return
        if self._is_binary(data):
            severity = "warning" if suffix in ARCHIVE_OR_EXECUTABLE_SUFFIXES else "info"
            code = "ARCHIVE_OR_EXECUTABLE" if severity == "warning" else "BINARY_FILE"
            self.add_finding(
                code,
                severity,
                normalized,
                "Binary content is included; content was not echoed.",
                source=source,
            )
            return

        text = data.decode("utf-8", "replace")
        self.scan_text(normalized, text, source)

    def _decode_zero_paths(self, data: bytes) -> list[str]:
        return [
            item.decode("utf-8", "surrogateescape")
            for item in data.split(b"\0")
            if item
        ]

    def staged_paths(self) -> list[str]:
        return self._decode_zero_paths(
            self.git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
        )

    def working_paths(self) -> list[str]:
        tracked = self._decode_zero_paths(
            self.git("diff", "--name-only", "--diff-filter=ACMR", "-z")
        )
        untracked = self._decode_zero_paths(
            self.git("ls-files", "--others", "--exclude-standard", "-z")
        )
        return list(dict.fromkeys([*tracked, *untracked]))

    def tree_paths(self) -> list[str]:
        return self._decode_zero_paths(self.git("ls-files", "-z"))

    def index_is_symlink(self, path: str) -> bool:
        raw = self.git("ls-files", "-s", "-z", "--", path)
        return raw.startswith(b"120000 ")

    def read_index_blob(self, path: str) -> bytes:
        return self.git("show", f":{path}", timeout=60)

    def scan_selected(self, kind: str, paths: Iterable[str]) -> None:
        for path in paths:
            try:
                if kind == "index":
                    data = self.read_index_blob(path)
                    symlink = self.index_is_symlink(path)
                else:
                    full = self.root / path
                    if not full.exists() and not full.is_symlink():
                        self.add_skip(path, "path no longer exists", kind)
                        continue
                    symlink = full.is_symlink()
                    data = os.readlink(full).encode("utf-8") if symlink else full.read_bytes()
                self.scan_blob(path, data, source=kind, symlink=symlink)
            except (OSError, RuntimeError) as exc:
                self.add_error(f"scan-{kind}", f"{_safe_path(path)}: {exc}")

    def scan_history(self) -> None:
        try:
            raw = self.git("rev-list", "--objects", "--all", timeout=60)
            object_paths: dict[str, str] = {}
            for line in raw.decode("utf-8", "surrogateescape").splitlines():
                if not line:
                    continue
                oid, _, path = line.partition(" ")
                object_paths.setdefault(oid, path or "<history-object>")
            if not object_paths:
                return
            batch_input = ("\n".join(object_paths) + "\n").encode("ascii")
            checked = self.git(
                "cat-file",
                "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                input_bytes=batch_input,
                timeout=60,
            )
            blob_count = 0
            for line in checked.decode("ascii", "replace").splitlines():
                fields = line.split()
                if len(fields) != 3 or fields[1] != "blob":
                    continue
                oid, _, size_text = fields
                size = int(size_text)
                blob_count += 1
                path = object_paths.get(oid, "<history-object>")
                if blob_count > self.max_history_blobs:
                    self.add_error(
                        "history",
                        f"history blob limit exceeded ({self.max_history_blobs}); scan incomplete",
                    )
                    break
                if size > self.max_file_bytes:
                    self.add_skip(path, "history blob exceeds max scan size", "history")
                    continue
                data = self.git("cat-file", "blob", oid, timeout=60)
                self.scan_blob(path, data, source="history")
        except (RuntimeError, ValueError) as exc:
            self.add_error("history", str(exc))

    def scan_commit_emails(self) -> None:
        try:
            raw = self.git("log", "--all", "--format=%ae%x00%ce%x00", timeout=60)
            emails = {
                item.decode("utf-8", "replace").strip()
                for item in raw.split(b"\0")
                if item.strip()
            }
            exposed = [email for email in emails if not self._is_safe_email(email)]
            if exposed:
                self.add_finding(
                    "COMMIT_EMAIL_EXPOSURE",
                    "high",
                    "<git-history>",
                    f"{len(exposed)} non-noreply commit email address(es) detected; values are redacted.",
                    source="history",
                )
        except RuntimeError as exc:
            self.add_error("commit-email", str(exc))

    def scan_remotes(self) -> None:
        try:
            names = self.git("remote").decode("utf-8", "replace").split()
            for name in names:
                urls = self.git("remote", "get-url", "--all", name).decode(
                    "utf-8", "replace"
                ).splitlines()
                for url in urls:
                    matched_secret = any(pattern.search(url) for _, _, pattern in SECRET_PATTERNS)
                    embedded = False
                    if re.match(r"(?i)^https?://", url):
                        try:
                            parsed = urlsplit(url)
                            embedded = bool(parsed.username or parsed.password)
                        except ValueError:
                            embedded = True
                    if matched_secret or embedded:
                        self.add_finding(
                            "REMOTE_CREDENTIAL",
                            "critical",
                            f"<git-remote:{_safe_text(name, 80)}>",
                            "Git remote contains embedded credential material; URL is redacted.",
                            source="metadata",
                        )
        except RuntimeError as exc:
            self.add_error("remotes", str(exc))

    def scan_repository_basics(self) -> None:
        names = {path.name.lower() for path in self.root.iterdir() if path.is_file()}
        if not any(name.startswith("readme") for name in names):
            self.add_finding(
                "README_MISSING",
                "warning",
                "<repository-root>",
                "No root README file was found.",
                source="metadata",
            )
        if not any(
            name == "license"
            or name.startswith("license.")
            or name == "copying"
            or name.startswith("copying.")
            for name in names
        ):
            self.add_finding(
                "LICENSE_MISSING",
                "warning",
                "<repository-root>",
                "No root LICENSE or COPYING file was found.",
                source="metadata",
            )
        if ".gitignore" not in names:
            self.add_finding(
                "GITIGNORE_MISSING",
                "warning",
                "<repository-root>",
                "No root .gitignore file was found.",
                source="metadata",
            )

    def run(self) -> dict[str, Any]:
        try:
            self.git("rev-parse", "--is-inside-work-tree")
        except RuntimeError as exc:
            self.add_error("repository", str(exc))
            return self.report()

        self.scan_repository_basics()
        self.scan_remotes()
        self.scan_commit_emails()

        if self.mode in {"staged", "all"}:
            self.scan_selected("index", self.staged_paths())
        if self.mode in {"working", "all"}:
            self.scan_selected("working", self.working_paths())
        if self.mode in {"tree", "all"}:
            self.scan_selected("tree", self.tree_paths())
        if self.mode in {"history", "all"}:
            self.scan_history()

        if self.candidates == 0:
            self.add_finding(
                "NO_CANDIDATES",
                "warning",
                "<release-scope>",
                "No candidate files were found for the selected mode.",
                source="metadata",
            )
        return self.report()

    def report(self) -> dict[str, Any]:
        counts = {severity: 0 for severity in SEVERITY_RANK}
        for finding in self.findings:
            counts[finding["severity"]] += 1
        if self.errors:
            verdict = "INCOMPLETE"
        elif counts["critical"] or counts["high"]:
            verdict = "NO-GO"
        elif counts["warning"]:
            verdict = "REVIEW"
        else:
            verdict = "GO"
        return {
            "schema_version": SCHEMA_VERSION,
            "repository": _safe_text(self.root.name, 120),
            "mode": self.mode,
            "summary": {
                "verdict": verdict,
                "candidates": self.candidates,
                "findings": len(self.findings),
                "errors": len(self.errors),
                "skipped": len(self.skipped),
                "counts": counts,
            },
            "findings": sorted(
                self.findings,
                key=lambda item: (
                    -SEVERITY_RANK[item["severity"]],
                    item["path"],
                    item["line"] or 0,
                    item["code"],
                ),
            ),
            "errors": self.errors,
            "skipped": self.skipped,
        }


def find_git_root(target: Path) -> Path:
    proc = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "--show-toplevel"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError("target is not inside a Git work tree")
    return Path(proc.stdout.decode("utf-8", "replace").strip()).resolve()


def format_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "Public release audit",
        f"repository={report['repository']}",
        f"mode={report['mode']}",
        f"verdict={summary['verdict']}",
        (
            f"candidates={summary['candidates']} findings={summary['findings']} "
            f"errors={summary['errors']} skipped={summary['skipped']}"
        ),
    ]
    for finding in report["findings"]:
        location = finding["path"]
        if finding["line"]:
            location += f":{finding['line']}"
        lines.append(
            f"[{finding['severity'].upper()}] {finding['code']} {location} "
            f"({finding['source']}): {finding['message']}"
        )
    for error in report["errors"]:
        lines.append(f"[ERROR] {error['stage']}: {error['message']}")
    for skipped in report["skipped"]:
        lines.append(
            f"[SKIPPED] {skipped['path']} ({skipped['source']}): {skipped['reason']}"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only, redacting pre-publication audit for a Git repository."
    )
    parser.add_argument("target", nargs="?", default=".", help="Repository path")
    parser.add_argument(
        "--mode",
        choices=("staged", "working", "tree", "history", "all"),
        default="staged",
        help="Release scope to inspect",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=2_000_000,
        help="Maximum bytes scanned per file/blob",
    )
    parser.add_argument(
        "--max-history-blobs",
        type=int,
        default=5_000,
        help="Maximum reachable history blobs scanned",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.max_file_bytes < 1 or args.max_history_blobs < 1:
        print("limits must be positive", file=sys.stderr)
        return 2
    try:
        root = find_git_root(Path(args.target).resolve())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "repository": _safe_text(Path(args.target).name or ".", 120),
            "mode": args.mode,
            "summary": {
                "verdict": "INCOMPLETE",
                "candidates": 0,
                "findings": 0,
                "errors": 1,
                "skipped": 0,
                "counts": {severity: 0 for severity in SEVERITY_RANK},
            },
            "findings": [],
            "errors": [{"stage": "repository", "message": _safe_text(str(exc))}],
            "skipped": [],
        }
    else:
        report = Audit(
            root,
            mode=args.mode,
            max_file_bytes=args.max_file_bytes,
            max_history_blobs=args.max_history_blobs,
        ).run()

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_text(report))

    verdict = report["summary"]["verdict"]
    if verdict == "GO":
        return 0
    if verdict == "INCOMPLETE":
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
