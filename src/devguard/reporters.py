"""JSON, SARIF v2.1.0, HTML, and terminal text report formatters."""

from __future__ import annotations

import html
import json
from typing import Any

from devguard.engine import ScanResult

_SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def render_text(result: ScanResult) -> str:
    lines = [
        f"DevGuard Scan Report — {result.root}",
        (
            f"Files scanned: {result.files_scanned} | "
            f"Findings: {len(result.findings)} | Suppressed: {result.suppressed_count}"
        ),
        f"Summary: {result.summary()}",
        "",
    ]
    for f in result.findings:
        lines.append(f"[{f.severity}] {f.rule_id} {f.file_path}:{f.line} — {f.title}: {f.message}")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        "root": result.root,
        "files_scanned": result.files_scanned,
        "suppressed_count": result.suppressed_count,
        "summary": result.summary(),
        "findings": [{**f.to_dict(), "fingerprint": f.fingerprint()} for f in result.findings],
    }
    return json.dumps(payload, indent=2)


def render_sarif(result: ScanResult, version: str = "0.3.0") -> str:
    """Render findings as a SARIF v2.1.0 document for GitHub Code Scanning."""
    rules_seen: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for f in result.findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message},
                "properties": {"category": f.category, "severity": f.severity},
            }
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL_MAP.get(f.severity, "warning"),
                "message": {"text": f"{f.title}: {f.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path.replace("\\", "/")},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": f.fingerprint()},
            }
        )

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DevGuard",
                        "version": version,
                        "informationUri": "https://github.com/fully-ai/devguard",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def render_html(result: ScanResult) -> str:
    summary = result.summary()
    rows = []
    for f in result.findings:
        rows.append(
            "<tr>"
            f"<td><span class='sev sev-{html.escape(f.severity)}'>{html.escape(f.severity)}</span></td>"
            f"<td><code>{html.escape(f.rule_id)}</code></td>"
            f"<td>{html.escape(f.category)}</td>"
            f"<td><code>{html.escape(f.file_path)}:{f.line}</code></td>"
            f"<td><strong>{html.escape(f.title)}</strong><br/><small>{html.escape(f.message)}</small></td>"
            "</tr>"
        )
    table_body = "\n".join(rows) or "<tr><td colspan='5'>No findings detected.</td></tr>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>DevGuard Security Report</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0d1117; color: #e6edf3; margin: 24px; }}
.cards {{ display: flex; gap: 12px; margin-bottom: 18px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 18px; }}
table {{ width: 100%; border-collapse: collapse; background: #161b22; }}
th, td {{ border-bottom: 1px solid #30363d; padding: 10px; text-align: left; font-size: 0.9rem; }}
.sev {{ padding: 2px 8px; border-radius: 999px; font-size: 0.78rem; font-weight: 700; }}
.sev-CRITICAL {{ background: #7f1d1d; color: #fecaca; }}
.sev-HIGH {{ background: #9a3412; color: #fed7aa; }}
.sev-MEDIUM {{ background: #854d0e; color: #fef08a; }}
.sev-LOW {{ background: #1e3a8a; color: #bfdbfe; }}
</style>
</head>
<body>
<h1>DevGuard Security Report</h1>
<p>Target: <code>{html.escape(result.root)}</code> | Files scanned: {result.files_scanned}</p>
<div class="cards">
  <div class="card">Critical: <strong>{summary['CRITICAL']}</strong></div>
  <div class="card">High: <strong>{summary['HIGH']}</strong></div>
  <div class="card">Medium: <strong>{summary['MEDIUM']}</strong></div>
  <div class="card">Low: <strong>{summary['LOW']}</strong></div>
</div>
<table>
  <thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Location</th><th>Details</th></tr></thead>
  <tbody>{table_body}</tbody>
</table>
</body>
</html>"""
