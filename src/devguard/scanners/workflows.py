"""GitHub Actions workflow security checks."""

from __future__ import annotations

import re

from devguard.models import Finding, GuardConfig

_USES_RE = re.compile(r"""^\s*(?:-\s*)?uses:\s*["']?([^"'\s#]+)["']?""")
_RUN_INJECT_RE = re.compile(
    r"""\$\{\{\s*(github\.event\.(?:issue|pull_request|comment|review|discussion|pages|commits|head_commit)\.[^}]+|github\.head_ref)\s*\}\}"""
)
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def scan_workflow_file(rel_path: str, text: str, cfg: GuardConfig) -> list[Finding]:
    """Inspect .github/workflows/*.yml files for common CI/CD security anti-patterns."""
    normalized = rel_path.replace("\\", "/")
    if not normalized.startswith(".github/workflows/") or not normalized.endswith((".yml", ".yaml")):
        return []

    findings: list[Finding] = []
    lines = text.splitlines()
    uses_pr_target = "pull_request_target" in text
    has_untrusted_checkout = "pull_request.head" in text

    if uses_pr_target and has_untrusted_checkout and "CI-003" not in cfg.disabled_rules:
        pr_target_line = next((i for i, ln in enumerate(lines, 1) if "pull_request_target" in ln), 1)
        findings.append(
            Finding(
                rule_id="CI-003",
                category="ci-cd",
                severity="CRITICAL",
                title="Unsafe pull_request_target Checkout",
                file_path=rel_path,
                line=pr_target_line,
                message=(
                    "pull_request_target combined with PR head checkout allows "
                    "untrusted code execution with repo secrets."
                ),
                snippet=lines[pr_target_line - 1].strip()[:120],
            )
        )

    for lineno, raw_line in enumerate(lines, start=1):
        if "devguard:ignore" in raw_line:
            continue
        stripped = raw_line.strip()
        if stripped.startswith("#"):
            continue

        if re.match(r"^permissions:\s*write-all\b", stripped) and "CI-005" not in cfg.disabled_rules:
            findings.append(
                Finding(
                    rule_id="CI-005",
                    category="ci-cd",
                    severity="HIGH",
                    title="Overly Permissive GITHUB_TOKEN (write-all)",
                    file_path=rel_path,
                    line=lineno,
                    message="Grant least-privilege explicit permissions instead of 'permissions: write-all'.",
                    snippet=stripped[:120],
                )
            )

        if _RUN_INJECT_RE.search(raw_line) and "CI-004" not in cfg.disabled_rules:
            findings.append(
                Finding(
                    rule_id="CI-004",
                    category="ci-cd",
                    severity="HIGH",
                    title="Potential GitHub Actions Script Injection",
                    file_path=rel_path,
                    line=lineno,
                    message=(
                        "Pass untrusted event context via an env: variable instead "
                        "of interpolating ${{ ... }} directly."
                    ),
                    snippet=stripped[:120],
                )
            )

        uses_match = _USES_RE.match(raw_line)
        if uses_match:
            ref = uses_match.group(1)
            if ref.startswith("./") or ref.startswith("docker://") or "@" not in ref:
                continue
            action_name, version = ref.rsplit("@", 1)
            if version in {"main", "master", "HEAD", "latest"}:
                if "CI-001" not in cfg.disabled_rules:
                    findings.append(
                        Finding(
                            rule_id="CI-001",
                            category="ci-cd",
                            severity="HIGH",
                            title="Action Pinned to Mutable Branch",
                            file_path=rel_path,
                            line=lineno,
                            message=(
                                f"Action '{action_name}' uses mutable ref '@{version}'; "
                                "pin to an immutable commit SHA."
                            ),
                            snippet=stripped[:120],
                        )
                    )
            elif not _SHA40_RE.match(version) and not action_name.startswith("actions/"):
                if "CI-002" not in cfg.disabled_rules:
                    findings.append(
                        Finding(
                            rule_id="CI-002",
                            category="ci-cd",
                            severity="MEDIUM",
                            title="Third-Party Action Not Pinned to Commit SHA",
                            file_path=rel_path,
                            line=lineno,
                            message=(
                                f"Third-party action '{action_name}@{version}' should be "
                                "pinned to a full 40-char commit SHA."
                            ),
                            snippet=stripped[:120],
                        )
                    )

    return findings
