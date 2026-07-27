# Codex Public Release Audit

[![Validate Skill](https://github.com/Fuika0306/codex-public-release-audit/actions/workflows/validate.yml/badge.svg)](https://github.com/Fuika0306/codex-public-release-audit/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A local, read-only, redacting release gate for Git repositories and Codex Skills.
It checks the content you are about to publish and reachable Git history without
printing matched secret or personal-data values.

## What it checks

- credential and private-key patterns
- personal email and public IP exposure
- sensitive filenames and local artifacts
- credential-bearing Git remotes
- staged, working-tree, tracked-tree, and reachable-history content
- symlinks and unexpected binaries
- GitHub Actions permissions and unpinned Actions
- commit email exposure

## Install as a Codex Skill

```powershell
$codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
Copy-Item -Recurse -Force .\skills\public-release-audit (Join-Path $codexHome 'skills\public-release-audit')
```

```bash
codex_home="${CODEX_HOME:-$HOME/.codex}"
cp -R skills/public-release-audit "$codex_home/skills/public-release-audit"
```

Restart or open a new Codex task after installation so the Skill inventory is
reloaded.

## Run directly

Full public-release gate, including reachable history:

```bash
python -X utf8 skills/public-release-audit/scripts/audit_release.py . --mode all --format json
```

Other scopes:

```bash
# Intended staged release
python -X utf8 skills/public-release-audit/scripts/audit_release.py . --mode staged --format json

# Current tracked tree
python -X utf8 skills/public-release-audit/scripts/audit_release.py . --mode tree --format json

# Working tree
python -X utf8 skills/public-release-audit/scripts/audit_release.py . --mode working --format json
```

## Verdicts and exit codes

| Verdict | Meaning | Exit code |
| --- | --- | ---: |
| `GO` | Completed scan with no warning, high, or critical finding | `0` |
| `REVIEW` | Warning-level exposure or release-hygiene issue remains | `1` |
| `NO-GO` | High or critical privacy, secret, workflow, remote, or symlink finding | `1` |
| `INCOMPLETE` | A scan error or limit prevented a complete result | `2` |

The JSON output reports rule code, severity, relative path, line number, and
source. It intentionally omits the matched value, remote URL, and symlink
target.

## Safety boundaries

- no staging, commits, pushes, history rewrites, or network calls
- no automatic remediation
- no matched credential, email, IP, remote URL, or symlink target in output
- a clean staged scan does not replace `--mode all` before a public release
- zero candidates, completed clean scans, skipped files, and errors remain
  separate states

## Repository layout

```text
skills/public-release-audit/
  SKILL.md
  agents/openai.yaml
  scripts/audit_release.py
  tests/test_audit_release.py
```

## Development

```bash
python -X utf8 tests/validate_skill.py
python -X utf8 skills/public-release-audit/tests/test_audit_release.py
```

The test suite uses disposable local Git repositories and fake credentials. It
does not call a network service.

## ????

?????????????? GitHub ??????????????
`--mode all` ????????? reachable Git history??????????
?????????????????????????Email ? IP ???

## License

[MIT](LICENSE)
