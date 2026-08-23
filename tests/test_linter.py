from pathlib import Path

from actions_safecheck.linter import scan_workflow


def write_workflow(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "workflow.yml"
    path.write_text(text, encoding="utf-8")
    return path


def codes(findings):
    return {item.code for item in findings}


def test_safe_read_only_workflow_has_no_findings(tmp_path):
    path = write_workflow(
        tmp_path,
        """name: CI
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - run: python -m pytest
""",
    )
    assert scan_workflow(path) == []


def test_flags_privileged_trigger_and_injection(tmp_path):
    path = write_workflow(
        tmp_path,
        """name: Unsafe
on:
  pull_request_target:
    types: [opened]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo ${{ github.event.pull_request.title }}
""",
    )
    found = scan_workflow(path)
    assert {"PR_TARGET_TRIGGER", "SCRIPT_INJECTION_RISK", "UNPINNED_ACTION", "MISSING_TOP_LEVEL_PERMISSIONS"} <= codes(found)


def test_flags_literal_secret_and_self_hosted_runner(tmp_path):
    path = write_workflow(
        tmp_path,
        """name: Risky
on: push
jobs:
  deploy:
    runs-on: self-hosted
    env:
      api_key: abcdefghijklmno
    steps:
      - run: echo ok
""",
    )
    found = scan_workflow(path)
    assert {"PLAINTEXT_SECRET_LIKE_VALUE", "PUBLIC_SELF_HOSTED_RUNNER_RISK"} <= codes(found)
