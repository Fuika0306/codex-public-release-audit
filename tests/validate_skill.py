#!/usr/bin/env python3
"""Validate the public repository without external dependencies or network access."""

from __future__ import annotations

import ast
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = 'public-release-audit'
SKILL_DIR = ROOT / "skills" / SKILL_NAME
REQUIRED = (
    ROOT / "README.md",
    ROOT / "LICENSE",
    ROOT / "SECURITY.md",
    ROOT / ".gitignore",
    ROOT / ".github" / "workflows" / "validate.yml",
    SKILL_DIR / "SKILL.md",
    SKILL_DIR / "agents" / "openai.yaml",
    SKILL_DIR / "scripts" / 'audit_release.py',
    SKILL_DIR / "tests" / 'test_audit_release.py',
)
FORBIDDEN_NAMES = {"auth.json", ".env", "id_rsa", "id_ed25519"}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


missing = [path.relative_to(ROOT).as_posix() for path in REQUIRED if not path.is_file()]
if missing:
    fail("missing required files: " + ", ".join(missing))

for path in ROOT.rglob("*"):
    if path.is_symlink():
        fail(f"symlink is not allowed: {path.relative_to(ROOT).as_posix()}")
    if not path.is_file() or ".git" in path.parts:
        continue
    relative = path.relative_to(ROOT).as_posix()
    if path.name in FORBIDDEN_NAMES or path.suffix == ".pyc" or "__pycache__" in path.parts:
        fail(f"local or credential artifact is not allowed: {relative}")
    if path.stat().st_size > 1_000_000:
        fail(f"unexpected file larger than 1 MB: {relative}")
    raw = path.read_bytes()
    if b"\x00" in raw:
        fail(f"binary file is not allowed: {relative}")
    if raw.startswith(b"\xef\xbb\xbf"):
        fail(f"UTF-8 BOM is not allowed: {relative}")

skill_text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
if not skill_text.startswith("---\n"):
    fail("SKILL.md must begin with YAML frontmatter")
parts = skill_text.split("---", 2)
if len(parts) != 3:
    fail("SKILL.md frontmatter is malformed")
frontmatter = parts[1]
name_match = re.search(r"(?m)^name:\s*([^\s]+)\s*$", frontmatter)
description_match = re.search(r"(?m)^description:\s*(.+)$", frontmatter)
if not name_match or name_match.group(1) != SKILL_NAME:
    fail("SKILL.md name does not match the repository Skill")
if not description_match or len(description_match.group(1).strip()) < 40:
    fail("SKILL.md description is missing or too short")

for path in (SKILL_DIR / "scripts").glob("*.py"):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
for path in (SKILL_DIR / "tests").glob("*.py"):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
if "pull_request_target:" in workflow:
    fail("pull_request_target is not allowed")
if "permissions:\n  contents: read" not in workflow:
    fail("workflow permissions must be read-only")
for line in workflow.splitlines():
    stripped = line.strip()
    if stripped.startswith("uses:") and not re.search(r"@[0-9a-f]{40}(?:\s|$)", stripped):
        fail(f"GitHub Action is not pinned to a full commit SHA: {stripped}")

print("PASS: public Skill structure and safety checks")
