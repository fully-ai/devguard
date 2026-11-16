"""Secret and high-entropy credential detection."""

from __future__ import annotations

import math
import re
from pathlib import Path

from devguard.models import Finding, GuardConfig

_SIGNATURE_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("SEC-001", "CRITICAL", "AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SEC-002", "CRITICAL", "GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}\b")),
    (
        "SEC-003",
        "CRITICAL",
        "Private Key Material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("SEC-004", "HIGH", "Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("SEC-005", "CRITICAL", "Stripe Live Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
]

_ASSIGNMENT_RE = re.compile(
    r"""(?i)\b(?:api_?key|secret|token|password|passwd|private_?key)\b\s*[:=]\s*["']([^"'\n]{8,})["']"""
)
_PLACEHOLDERS = ("example", "changeme", "replace", "dummy", "placeholder", "your_", "test_secret", "xxxx")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def scan_secrets(path: Path, rel_path: str, text: str, cfg: GuardConfig) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "devguard:ignore" in line:
            continue

        matched_sig = False
        for rule_id, severity, title, pattern in _SIGNATURE_RULES:
            if rule_id in cfg.disabled_rules:
                continue
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category="secrets",
                        severity=severity,
                        title=title,
                        file_path=rel_path,
                        line=lineno,
                        message=f"Potential {title} detected in source.",
                    )
                )
                matched_sig = True

        if not matched_sig and "SEC-006" not in cfg.disabled_rules:
            for match in _ASSIGNMENT_RE.finditer(line):
                val = match.group(1)
                low = val.lower()
                if any(ph in low for ph in _PLACEHOLDERS) or val.startswith("${"):
                    continue
                if len(val) >= cfg.min_secret_length and shannon_entropy(val) >= cfg.entropy_threshold:
                    findings.append(
                        Finding(
                            rule_id="SEC-006",
                            category="secrets",
                            severity="HIGH",
                            title="High-Entropy Hardcoded Credential",
                            file_path=rel_path,
                            line=lineno,
                            message="High-entropy literal assigned to sensitive identifier.",
                        )
                    )
    return findings
