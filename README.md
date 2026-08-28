# Actions Safecheck: GitHub Actions Workflow Security Linter

**Find high-signal GitHub Actions workflow risks before they reach CI.**

`actions-safecheck` is a read-only, local-first linter for GitHub Actions workflow files. It flags privileged pull-request triggers, direct shell interpolation of GitHub context, mutable third-party actions, missing least-privilege permissions, literal secret-like values, untrusted checkout refs, and self-hosted runners.

## Why this exists

GitHub Actions workflows are executable infrastructure. A small change to a trigger, permission, checkout ref, or shell expression can change who is trusted and what a workflow can access. This project turns a focused subset of those risks into reviewable findings that can run before CI or inside CI.

| Use case | What it gives you |
|---|---|
| Pull-request review | A fast, read-only check for dangerous workflow patterns. |
| Repository onboarding | Actionable remediation text for maintainers and contributors. |
| CI guardrails | Stable text or JSON output with configurable failure thresholds. |
| Security education | Small examples that make workflow risks easy to inspect. |

## Three-minute quick start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install actions-safecheck
cd path/to/your/repository
actions-safecheck .
```

To scan one workflow or produce machine-readable output:

```bash
actions-safecheck .github/workflows/ci.yml
actions-safecheck . --format json
```

To make warnings fail the command as well as errors:

```bash
actions-safecheck . --fail-on warning
```

The command is read-only. A repository path scans `.github/workflows/*.yml` and `.yaml`; a file path scans only that workflow.

## Example output

```text
ERROR   PR_TARGET_TRIGGER             repo/.github/workflows/ci.yml:4 — pull_request_target runs privileged workflow code in response to untrusted pull requests.
         Remediation: Prefer pull_request, or isolate privileged follow-up work and never execute untrusted checkout content with secrets.
WARNING UNPINNED_ACTION               repo/.github/workflows/ci.yml:11 — Third-party action actions/checkout is referenced by mutable ref 'v4'.
         Remediation: Pin actions to a reviewed commit SHA or an explicitly verified immutable release.
```

## What it checks

| Code | Severity | Meaning |
|---|---|---|
| `PR_TARGET_TRIGGER` | Error | A workflow uses `pull_request_target`. |
| `UNTRUSTED_CHECKOUT_REF` | Error | A pull-request head ref appears near a checkout step. |
| `SCRIPT_INJECTION_RISK` | Error | A `run:` command directly interpolates GitHub context or a secret expression. |
| `PLAINTEXT_SECRET_LIKE_VALUE` | Error | A secret-like key contains a literal value. |
| `WRITE_ALL_PERMISSIONS` | Error | Global `write-all` permissions are declared. |
| `GLOBAL_CONTENTS_WRITE` | Warning | Contents write access appears to be global rather than job-scoped. |
| `UNPINNED_ACTION` | Warning | A third-party action uses a mutable ref instead of a full commit SHA. |
| `PUBLIC_SELF_HOSTED_RUNNER_RISK` | Warning | A self-hosted runner is selected. |
| `MISSING_TOP_LEVEL_PERMISSIONS` | Warning | No top-level permissions policy is declared. |

## CI usage

```yaml
name: Workflow safety

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      # Replace these illustrative values with reviewed commit SHAs.
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - uses: actions/setup-python@0123456789abcdef0123456789abcdef01234567
        with:
          python-version: '3.12'
      - run: python -m pip install .
      - run: actions-safecheck . --fail-on error
```

The SHA values above are deliberately illustrative and are not verified releases. Pin each action to a reviewed full-length commit SHA in the workflow that you deploy.

## Safe defaults and honest limitations

The scanner performs no network access, does not execute workflow code, and does not modify files. It is a static heuristic, not a replacement for CodeQL, OpenSSF Scorecards, secret-scanning services, or human review. YAML anchors, generated workflows, reusable workflows, composite actions, and complex multiline shell semantics may require manual review. A warning is not proof of exploitability, and a clean result is not proof of security. The literal-secret detector is deliberately conservative and may miss encoded or split secrets.

The project is provided for defensive repository hygiene. Review findings in context before changing a workflow, especially for deployment and release automation.

## Development

```bash
git clone https://github.com/varungor365/actions-safecheck
cd actions-safecheck
python -m pip install -e '.[test]'
pytest -q
python -m compileall -q src tests
```

## References

The checks are informed by [GitHub's secure use reference](https://docs.github.com/en/actions/reference/security/secure-use), including its guidance on least-privilege tokens, untrusted pull requests, secret handling, third-party actions, and dependency review.

## License

MIT. See [LICENSE](LICENSE).
