"""Conservative, offline Python AST checks for AEAD nonce assumptions.

Findings are hypotheses: static syntax cannot establish runtime key/nonce reuse.
No literals, variable values, or source excerpts are included in evidence.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

_AEAD = {"AESGCM", "ChaCha20Poly1305"}


def _literal_nonce(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    """Recognize a few syntactically fixed byte-valued nonce expressions."""
    if isinstance(node, ast.Name):
        return node.id in constants and _literal_nonce(constants[node.id], {})
    if isinstance(node, ast.Constant):
        return isinstance(node.value, bytes)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        return ((isinstance(node.left, ast.Constant) and isinstance(node.left.value, bytes)
                 and isinstance(node.right, ast.Constant) and isinstance(node.right.value, int))
                or (isinstance(node.right, ast.Constant) and isinstance(node.right.value, bytes)
                    and isinstance(node.left, ast.Constant) and isinstance(node.left.value, int)))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return (node.func.attr == "fromhex" and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "bytes" and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str))
    return False


def check_python_aead_nonces(source: str, file_label: str) -> list[dict[str, Any]]:
    """Flag statically fixed nonces passed to recognized AEAD encrypt calls."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    constructors = set(_AEAD)
    instances: set[str] = set()
    constants: dict[str, ast.AST] = {}
    findings: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "cryptography.hazmat.primitives.ciphers.aead":
            for alias in node.names:
                if alias.name in _AEAD:
                    constructors.add(alias.asname or alias.name)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in constructors:
                        instances.add(target.id)
                    elif isinstance(value, (ast.Constant, ast.BinOp, ast.Call)):
                        constants[target.id] = value
                    else:
                        constants.pop(target.id, None)
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "encrypt" or not isinstance(node.func.value, ast.Name):
            continue
        if node.func.value.id not in instances:
            continue
        nonce = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "nonce"), None)
        if nonce is None or not _literal_nonce(nonce, constants):
            continue
        findings.append({
            "rule": "CRYPTO-AEAD-STATIC-NONCE",
            "target": file_label,
            "title": "Statically fixed AEAD encryption nonce",
            "priority": "review",
            "status": "UNCONFIRMED — needs owner validation",
            "evidence_class": "static_code_finding",
            "evidence": {"file": file_label, "line": node.lineno, "nonce_class": "syntactically fixed"},
            "remediation": "Ensure nonce uniqueness for every encryption under the same key; use a verified nonce-management design.",
            "validation_needed": "Owner must verify runtime nonce generation, key lifecycle, and whether the encrypt call is reachable.",
        })
    return findings
