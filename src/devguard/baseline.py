"""Baseline generation and suppression helpers for DevGuard."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from devguard.models import Finding


def load_baseline_fingerprints(path: Path) -> set[str]:
    """Load suppressed finding fingerprints from a baseline JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    raw_entries: list[dict[str, Any]] = data.get("findings", [])
    return {str(entry["fingerprint"]) for entry in raw_entries if "fingerprint" in entry}


def filter_with_baseline(findings: list[Finding], baseline_path: Path) -> tuple[list[Finding], int]:
    """Filter out findings already present in the baseline file."""
    known = load_baseline_fingerprints(baseline_path)
    kept: list[Finding] = []
    suppressed = 0
    for f in findings:
        if f.fingerprint() in known:
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed


def render_baseline(root: str, findings: list[Finding]) -> str:
    """Serialize findings into a stable baseline JSON document."""
    entries = [
        {
            "fingerprint": f.fingerprint(),
            "rule_id": f.rule_id,
            "severity": f.severity,
            "file_path": f.file_path,
            "line": f.line,
            "title": f.title,
        }
        for f in findings
    ]
    payload = {
        "version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "root": root,
        "count": len(entries),
        "findings": entries,
    }
    return json.dumps(payload, indent=2)
