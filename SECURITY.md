# Security Policy

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Fuika0306/codex-public-release-audit/security/advisories/new).
Do not place credentials, personal data, private repository content, or scanner
match values in a public issue.

If a real credential was exposed, revoke or rotate it before preparing a
report. Include only the rule code, affected version or commit, operating
system, Python version, and a minimal synthetic reproduction.

## Scope

Security reports are especially useful for:

- scanner output that reveals a matched value
- missed credential classes with a synthetic reproduction
- Git history or path traversal mistakes
- symlink handling errors
- commands that mutate a target repository
- GitHub Actions permission regressions
