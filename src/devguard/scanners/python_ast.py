"""Python AST static security analysis."""

from __future__ import annotations

import ast

from devguard.models import Finding, GuardConfig


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    return ""


def scan_python_ast(rel_path: str, text: str, cfg: GuardConfig) -> list[Finding]:
    try:
        tree = ast.parse(text, filename=rel_path)
    except SyntaxError:
        return []

    lines = text.splitlines()
    findings: list[Finding] = []

    def add(rule_id: str, severity: str, title: str, node: ast.AST, msg: str) -> None:
        if rule_id in cfg.disabled_rules:
            return
        lineno = getattr(node, "lineno", 1)
        if 1 <= lineno <= len(lines) and "devguard:ignore" in lines[lineno - 1]:
            return
        findings.append(
            Finding(
                rule_id=rule_id,
                category="sast",
                severity=severity,
                title=title,
                file_path=rel_path,
                line=lineno,
                message=msg,
                snippet=lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else "",
            )
        )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name in {"eval", "exec"}:
            add(
                "PY-001",
                "HIGH",
                f"Dynamic Code Execution ({name})",
                node,
                f"Avoid calling {name}() on untrusted input.",
            )
        elif name == "os.system":
            add(
                "PY-002",
                "HIGH",
                "Shell Command Execution",
                node,
                "Use subprocess.run(..., shell=False) instead of os.system().",
            )
        elif name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    add(
                        "PY-003",
                        "HIGH",
                        "Subprocess Shell Injection Risk",
                        node,
                        "Avoid shell=True in subprocess calls.",
                    )
        elif name in {"pickle.loads", "pickle.load"}:
            add(
                "PY-004",
                "HIGH",
                "Unsafe Deserialization (pickle)",
                node,
                "pickle deserialization can execute arbitrary code.",
            )
        elif name == "yaml.load":
            has_safe = any(
                kw.arg == "Loader" and isinstance(kw.value, ast.Attribute) and "Safe" in kw.value.attr
                for kw in node.keywords
            )
            if not has_safe:
                add("PY-005", "HIGH", "Unsafe YAML Load", node, "Use yaml.safe_load() or SafeLoader.")
        elif name in {"hashlib.md5", "hashlib.sha1"}:
            used_for_sec = any(
                kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                for kw in node.keywords
            )
            if not used_for_sec:
                add(
                    "PY-006",
                    "MEDIUM",
                    f"Weak Hash Function ({name})",
                    node,
                    "Prefer SHA-256 or set usedforsecurity=False.",
                )
        elif name in {"requests.get", "requests.post", "requests.request", "httpx.get", "httpx.post"}:
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    add(
                        "PY-007",
                        "HIGH",
                        "TLS Verification Disabled",
                        node,
                        "Never disable TLS certificate verification (verify=False).",
                    )

    return findings
