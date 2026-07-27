---
name: public-release-audit
description: Run a read-only, redacting pre-publication gate for a Git repository before making it public, publishing it to GitHub, pushing an open-source release, or answering whether the repository leaks secrets or personal data. Inspect staged, working-tree, tracked-tree, or reachable-history content for credentials, personal email and public IP exposure, sensitive filenames, local artifacts, symlinks, binaries, credential-bearing remotes, commit email exposure, GitHub Actions permissions, and unpinned Actions. Use when the user asks to publish/share/open-source a repository, audit it before GitHub upload, or verify that no private data will be exposed.
---

# Public Release Audit

Use the bundled scanner as a release gate, not as a publisher.

## Workflow

1. Confirm the intended repository and release scope.
2. Run a local scan:
   - Intended staged change:
     `python -X utf8 scripts/audit_release.py TARGET --mode staged --format json`
   - Current tracked repository:
     `python -X utf8 scripts/audit_release.py TARGET --mode tree --format json`
   - Full public-release gate, including reachable Git history:
     `python -X utf8 scripts/audit_release.py TARGET --mode all --format json`
3. Keep match values redacted. Report only finding type, severity, path, line, source, and remediation.
4. Separate confirmed findings, scanner errors, and skipped files. An incomplete scan is not a pass.
5. Fix findings with the smallest local change, then rerun the same mode.
6. Hand off to the GitHub publishing workflow only after the audit returns `GO`.

## Verdicts

- `GO`: no warning, high, or critical finding and no scanner error.
- `REVIEW`: warning-level exposure or release hygiene issue remains.
- `NO-GO`: high or critical secret, privacy, symlink, workflow, or remote finding remains.
- `INCOMPLETE`: a scanner error or configured limit prevented a complete result.

Exit codes are `0` for `GO`, `1` for `REVIEW` or `NO-GO`, and `2` for `INCOMPLETE`.

## Boundaries

- The scanner is local and read-only. It must not stage, commit, push, rewrite history, change remotes, or call a network service.
- Never echo a matched credential, email address, public IP, private hostname, remote URL, or symlink target.
- Do not treat a clean staged scan as proof that reachable Git history is clean. Use `--mode all` before making an existing repository public.
- Do not automatically rewrite history. Present the affected path/source and obtain explicit approval for any later history rewrite.
- Preserve zero-result semantics: distinguish no candidates from a clean completed scan.

## Output Contract

Return:

1. One-line verdict.
2. Scope and candidate count.
3. Severity counts.
4. Findings ordered by severity.
5. Scanner errors and skipped files.
6. Minimal remediation order.
7. Exact rerun command.
