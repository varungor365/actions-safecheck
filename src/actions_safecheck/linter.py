"""Read-only GitHub Actions workflow safety checks."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)@([^\s#]+)")
_RUN = re.compile(r"^\s*-?\s*run:\s*(.*)$")
_EXPR = re.compile(
    r"\$\{\{\s*(github\.(?:event|head_ref|base_ref|ref_name)|"
    r"secrets\.[^}\s]+)"
)
_SECRET = re.compile(
    r"(?i)^\s*(?:api[_-]?key|token|password|secret|private[_-]?key)\s*:\s*"
    r"(?!\$\{\{\s*secrets\.)['\"]?([A-Za-z0-9_./+=-]{8,})"
)


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    line: int
    message: str
    remediation: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def _finding(
    severity: str,
    code: str,
    path: Path,
    line: int,
    message: str,
    remediation: str,
) -> Finding:
    return Finding(severity, code, str(path), line, message, remediation)


def scan_workflow(path: Path) -> list[Finding]:
    """Scan one workflow file without executing or modifying it."""
    lines = path.read_text(encoding="utf-8").splitlines()
    findings: list[Finding] = []
    has_top_level_permissions = False
    checkout_line: int | None = None

    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if re.match(r"^permissions\s*:", raw):
            has_top_level_permissions = True
            value = raw.split(":", 1)[1].strip()
            if value == "write-all":
                findings.append(
                    _finding(
                        "error",
                        "WRITE_ALL_PERMISSIONS",
                        path,
                        number,
                        "The workflow grants write-all permissions globally.",
                        "Set top-level permissions to read-only and grant narrowly scoped write access per job.",
                    )
                )
            elif "contents: write" in "\n".join(lines[number - 1 : number + 8]):
                findings.append(
                    _finding(
                        "warning",
                        "GLOBAL_CONTENTS_WRITE",
                        path,
                        number,
                        "The workflow appears to grant contents: write at workflow scope.",
                        "Move write access into the smallest job that needs it and keep the global default read-only.",
                    )
                )

        if re.match(r"^\s*pull_request_target\s*:", raw):
            findings.append(
                _finding(
                    "error",
                    "PR_TARGET_TRIGGER",
                    path,
                    number,
                    "pull_request_target runs privileged workflow code in response to untrusted pull requests.",
                    "Prefer pull_request, or isolate privileged follow-up work and never execute untrusted checkout content with secrets.",
                )
            )

        if "actions/checkout@" in raw:
            checkout_line = number
        elif checkout_line is not None and number - checkout_line <= 12:
            if "github.event.pull_request.head" in raw or "github.head_ref" in raw:
                findings.append(
                    _finding(
                        "error",
                        "UNTRUSTED_CHECKOUT_REF",
                        path,
                        number,
                        "The checkout step appears to use a pull-request head ref near actions/checkout.",
                        "Do not check out untrusted code in a privileged workflow; use an unprivileged pull_request job instead.",
                    )
                )
                checkout_line = None

        uses_match = _USES.match(raw)
        if uses_match:
            action, ref = uses_match.groups()
            if not action.startswith("./") and not _SHA.fullmatch(ref):
                findings.append(
                    _finding(
                        "warning",
                        "UNPINNED_ACTION",
                        path,
                        number,
                        f"Third-party action {action} is referenced by mutable ref {ref!r}.",
                        "Pin actions to a reviewed commit SHA or an explicitly verified immutable release.",
                    )
                )

        run_match = _RUN.match(raw)
        if run_match and _EXPR.search(run_match.group(1)):
            findings.append(
                _finding(
                    "error",
                    "SCRIPT_INJECTION_RISK",
                    path,
                    number,
                    "A shell command interpolates GitHub context or secret expressions directly.",
                    "Pass untrusted values through environment variables and validate them before use; avoid putting secrets in command text.",
                )
            )

        if "runs-on:" in raw and ("self-hosted" in raw or "[self-hosted" in raw):
            findings.append(
                _finding(
                    "warning",
                    "PUBLIC_SELF_HOSTED_RUNNER_RISK",
                    path,
                    number,
                    "The workflow selects a self-hosted runner, which is unsafe for public-repository untrusted code by default.",
                    "Use GitHub-hosted ephemeral runners or document strict isolation and trust boundaries.",
                )
            )

        secret_match = _SECRET.match(raw)
        if secret_match and "${{" not in raw:
            findings.append(
                _finding(
                    "error",
                    "PLAINTEXT_SECRET_LIKE_VALUE",
                    path,
                    number,
                    "A secret-like key appears to contain a literal value in the workflow.",
                    "Store sensitive values in GitHub Secrets or OIDC-backed short-lived credentials; never commit plaintext secrets.",
                )
            )

    if not has_top_level_permissions:
        findings.append(
            _finding(
                "warning",
                "MISSING_TOP_LEVEL_PERMISSIONS",
                path,
                1,
                "The workflow does not declare a top-level permissions policy.",
                "Declare permissions: contents: read at workflow scope and elevate individual jobs only when required.",
            )
        )

    return findings


def workflow_paths(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    workflow_dir = root / ".github" / "workflows"
    search_root = workflow_dir if workflow_dir.exists() else root
    yield from sorted(
        path
        for path in search_root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    )


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in workflow_paths(root):
        findings.extend(scan_workflow(path))
    return findings


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "No workflow safety findings."
    rows = [
        f"{item.severity.upper():7} {item.code:30} {item.path}:{item.line} — {item.message}\n"
        f"         Remediation: {item.remediation}"
        for item in findings
    ]
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Read-only GitHub Actions workflow safety linter"
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository or workflow path")
    parser.add_argument("--format", choices={"text", "json"}, default="text")
    parser.add_argument(
        "--fail-on",
        choices={"error", "warning", "none"},
        default="error",
        help="Exit 1 when findings at or above this severity exist",
    )
    args = parser.parse_args(argv)
    findings = scan(Path(args.path).resolve())
    if args.format == "json":
        print(json.dumps([item.to_dict() for item in findings], indent=2))
    else:
        print(render_text(findings))
    if args.fail_on == "none":
        return 0
    threshold = {"error": 0, "warning": 1}[args.fail_on]
    severity_value = {"error": 0, "warning": 1}
    return int(any(severity_value[item.severity] <= threshold for item in findings))


if __name__ == "__main__":
    raise SystemExit(main())
