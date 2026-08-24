# Actions Safecheck

**Read-only GitHub Actions workflow safety linter for public repositories.** `actions-safecheck` finds high-signal workflow hazards before they reach CI: privileged pull-request triggers, direct shell interpolation of GitHub context, mutable third-party actions, missing least-privilege permissions, literal secret-like values, untrusted checkout refs, and self-hosted runners.

## Why star this repository?

Star this repository if you want a small, dependency-light guardrail that is safe to run locally or in CI, produces actionable remediation text, and never edits workflows or contacts GitHub. It is intentionally narrower than a complete security platform, so its behavior is easy to inspect and extend.

## Three-minute quick start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install actions-safecheck
cd path/to/your/repository
actions-safecheck .
```

To get machine-readable output:

```bash
actions-safecheck . --format json
```

To fail on warnings as well as errors:

```bash
actions-safecheck . --fail-on warning
```

The command is read-only. It scans `.github/workflows/*.yml` and `.yaml` files when given a repository path, or scans one workflow when given a file path.

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
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - uses: actions/setup-python@0123456789abcdef0123456789abcdef01234567
        with:
          python-version: '3.12'
      - run: pip install .
      - run: actions-safecheck . --fail-on error
```

Use reviewed commit SHAs for the actions in your own workflow; the placeholder-looking SHA above is only an illustrative example and is not a verified release.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
pytest -q
python -m compileall -q src tests
```

## Safe defaults and limitations

The scanner performs no network access, does not execute workflow code, and does not modify files. It is a static heuristic, not a replacement for CodeQL, OpenSSF Scorecards, secret-scanning services, or human review. YAML anchors, generated workflows, reusable workflows, composite actions, and complex multiline shell semantics may require manual review. A warning is not proof of exploitability, and a clean result is not proof of security. The literal-secret detector is deliberately conservative and may miss encoded or split secrets.

The project is provided for defensive repository hygiene. Review findings in context before changing a workflow, especially for deployment and release automation.

## References

The checks are informed by [GitHub’s secure use reference](https://docs.github.com/en/actions/reference/security/secure-use) and its guidance on least privilege, untrusted pull requests, secret handling, and dependency review.

## License

MIT. See [LICENSE](LICENSE).
