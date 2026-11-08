"""Conservative, offline Python AST checks for AEAD nonce assumptions.

Findings are hypotheses: static syntax cannot establish runtime key/nonce reuse.
Names are tracked per lexical scope. Parameters, loop targets, and rebinding
clear a fixed-nonce conclusion. No literals, variable values, or source excerpts
are included in evidence.

Limits: attribute receivers such as ``self.aead`` are not tracked, helper
return values are not inlined, and a value is treated as fixed after ``if``,
``for``, or ``while`` only when every branch agrees.
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any

from decrypto_taxonomy import classify

_AEAD = {"AESGCM", "ChaCha20Poly1305"}
_AEAD_MODULE = "cryptography.hazmat.primitives.ciphers.aead"
_MATCH = getattr(ast, "Match", None)
_TRY_TYPES = tuple(cls for cls in (ast.Try, getattr(ast, "TryStar", None)) if cls is not None)


class _Missing:
    pass


_MISSING = _Missing()


class _Scope:
    def __init__(self) -> None:
        self.constructors: dict[str, bool] = {}
        self.instances: dict[str, bool] = {}
        self.constants: dict[str, Any] = {}


def _expr_is_static_nonce(node: ast.AST) -> bool:
    """Recognize a syntactically fixed byte expression with no name lookup."""
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


def _lookup(scopes: list[_Scope], table: str, name: str) -> Any:
    for scope in reversed(scopes):
        mapping = getattr(scope, table)
        if name in mapping:
            return mapping[name]
    return _MISSING


def _is_constructor(scopes: list[_Scope], name: str) -> bool:
    return _lookup(scopes, "constructors", name) is True


def _is_instance(scopes: list[_Scope], name: str) -> bool:
    return _lookup(scopes, "instances", name) is True


def _static_nonce(node: ast.AST, scopes: list[_Scope]) -> bool:
    if isinstance(node, ast.NamedExpr):
        return _static_nonce(node.value, scopes)
    if isinstance(node, ast.Name):
        value = _lookup(scopes, "constants", node.id)
        if value is _MISSING or value is None:
            return False
        return _expr_is_static_nonce(value)
    return _expr_is_static_nonce(node)


def _static_binding_value(value: ast.AST, scopes: list[_Scope]) -> ast.AST | None:
    node: ast.AST | None = value
    if isinstance(node, ast.Name):
        referred = _lookup(scopes, "constants", node.id)
        if referred is _MISSING or referred is None:
            return None
        node = referred
    if isinstance(node, ast.AST) and _expr_is_static_nonce(node):
        return node
    return None


def _bind_dynamic(scope: _Scope, name: str) -> None:
    scope.constructors[name] = False
    scope.instances[name] = False
    scope.constants[name] = None


def _bind(scope: _Scope, name: str, value: ast.AST, scopes: list[_Scope]) -> None:
    is_instance = (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                   and _is_constructor(scopes, value.func.id))
    static_value = None if is_instance else _static_binding_value(value, scopes)
    scope.constructors[name] = False
    scope.instances[name] = bool(is_instance)
    scope.constants[name] = static_value


def _snapshot(scope: _Scope) -> tuple[dict[str, bool], dict[str, bool], dict[str, Any]]:
    return (dict(scope.constructors), dict(scope.instances), dict(scope.constants))


def _restore(scope: _Scope, snap: tuple[dict[str, bool], dict[str, bool], dict[str, Any]]) -> None:
    scope.constructors = dict(snap[0])
    scope.instances = dict(snap[1])
    scope.constants = dict(snap[2])


def _state_key(snap: tuple[dict[str, bool], dict[str, bool], dict[str, Any]], name: str) -> tuple[Any, Any, Any]:
    constructors, instances, constants = snap
    constant = constants[name] if name in constants else _MISSING
    if isinstance(constant, ast.AST):
        constant_key = ast.dump(constant)
    else:
        constant_key = constant
    return (
        constructors[name] if name in constructors else _MISSING,
        instances[name] if name in instances else _MISSING,
        constant_key,
    )


def _merge(scope: _Scope, before: tuple[dict[str, bool], dict[str, bool], dict[str, Any]],
           snaps: list[tuple[dict[str, bool], dict[str, bool], dict[str, Any]]]) -> None:
    """Keep a binding only when every branch ends with the same conclusion."""
    names: set[str] = set(before[0]) | set(before[1]) | set(before[2])
    for snap in snaps:
        names |= set(snap[0]) | set(snap[1]) | set(snap[2])
    constructors: dict[str, bool] = {}
    instances: dict[str, bool] = {}
    constants: dict[str, Any] = {}
    for name in names:
        states = []
        for snap in snaps:
            state = _state_key(snap, name)
            if state == (_MISSING, _MISSING, _MISSING):
                state = _state_key(before, name)
            states.append(state)
        if states and all(state == states[0] for state in states):
            chosen = snaps[0]
            for snap in snaps:
                if name in snap[0] or name in snap[1] or name in snap[2]:
                    chosen = snap
                    break
            else:
                chosen = before
            if name not in chosen[0] and name not in chosen[1] and name not in chosen[2]:
                chosen = before
            if name in chosen[0]:
                constructors[name] = chosen[0][name]
            if name in chosen[1]:
                instances[name] = chosen[1][name]
            if name in chosen[2]:
                constants[name] = chosen[2][name]
        else:
            constructors[name] = False
            instances[name] = False
            constants[name] = None
    scope.constructors = constructors
    scope.instances = instances
    scope.constants = constants


def _all_args(args: ast.arguments) -> list[str]:
    names = [arg.arg for group in (args.posonlyargs, args.args, args.kwonlyargs) for arg in group]
    if args.vararg:
        names.append(args.vararg.arg)
    if args.kwarg:
        names.append(args.kwarg.arg)
    return names


def _bind_target(target: ast.AST, value: ast.AST | None, scopes: list[_Scope], emit: Any) -> None:
    if isinstance(target, ast.Name):
        if value is None:
            _bind_dynamic(scopes[-1], target.id)
        else:
            _bind(scopes[-1], target.id, value, scopes)
        return
    if isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _bind_target(elt, None, scopes, emit)
        return
    if isinstance(target, ast.Starred):
        _bind_target(target.value, None, scopes, emit)
        return
    _walk_expr(target, scopes, emit)


def _bind_import(scope: _Scope, node: ast.Import) -> None:
    for alias in node.names:
        _bind_dynamic(scope, alias.asname or alias.name.split(".")[0])


def _bind_import_from(scope: _Scope, node: ast.ImportFrom) -> None:
    for alias in node.names:
        if alias.name == "*":
            trusted = not node.level and node.module == _AEAD_MODULE
            for name in _AEAD:
                scope.constructors[name] = trusted
                scope.instances[name] = False
                scope.constants[name] = None
            continue
        local = alias.asname or alias.name
        trusted = (not node.level and node.module == _AEAD_MODULE and alias.name in _AEAD)
        scope.constructors[local] = trusted
        scope.instances[local] = False
        scope.constants[local] = None


def _nonce_arg(node: ast.Call) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == "nonce":
            return keyword.value
    if node.args:
        return node.args[0]
    return None


def _consider_encrypt(node: ast.Call, scopes: list[_Scope], emit: Any) -> None:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "encrypt":
        return
    if not isinstance(node.func.value, ast.Name) or not _is_instance(scopes, node.func.value.id):
        return
    nonce = _nonce_arg(node)
    if nonce is None or not _static_nonce(nonce, scopes):
        return
    emit(node)


def _walk_expr(node: ast.AST | None, scopes: list[_Scope], emit: Any) -> None:
    if node is None:
        return
    if isinstance(node, ast.Lambda):
        _walk_lambda(node, scopes, emit)
        return
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        _walk_comp((node.elt,), node.generators, scopes, emit)
        return
    if isinstance(node, ast.DictComp):
        _walk_comp((node.key, node.value), node.generators, scopes, emit)
        return
    if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
        _walk_expr(node.value, scopes, emit)
        _bind(scopes[-1], node.target.id, node.value, scopes)
        return
    if isinstance(node, ast.Call):
        _consider_encrypt(node, scopes, emit)
    for child in ast.iter_child_nodes(node):
        _walk_expr(child, scopes, emit)


def _walk_comp(elts: tuple[ast.AST, ...], generators: list[ast.comprehension], scopes: list[_Scope], emit: Any) -> None:
    def rec(index: int) -> None:
        if index == len(generators):
            for elt in elts:
                _walk_expr(elt, scopes, emit)
            return
        generator = generators[index]
        _walk_expr(generator.iter, scopes, emit)
        scopes.append(_Scope())
        _bind_target(generator.target, None, scopes, emit)
        for test in generator.ifs:
            _walk_expr(test, scopes, emit)
        rec(index + 1)
        scopes.pop()

    rec(0)


def _walk_lambda(node: ast.Lambda, scopes: list[_Scope], emit: Any) -> None:
    for default in list(node.args.defaults) + [item for item in node.args.kw_defaults if item]:
        _walk_expr(default, scopes, emit)
    inner = _Scope()
    for name in _all_args(node.args):
        _bind_dynamic(inner, name)
    scopes.append(inner)
    _walk_expr(node.body, scopes, emit)
    scopes.pop()


def _walk_function(node: ast.FunctionDef | ast.AsyncFunctionDef, scopes: list[_Scope], emit: Any,
                   bind_enclosing: bool = True) -> None:
    for decorator in node.decorator_list:
        _walk_expr(decorator, scopes, emit)
    for default in list(node.args.defaults) + [item for item in node.args.kw_defaults if item]:
        _walk_expr(default, scopes, emit)
    # A class method name lives on the class, not in the enclosing function or module.
    if bind_enclosing:
        _bind_dynamic(scopes[-1], node.name)
    inner = _Scope()
    for name in _all_args(node.args):
        _bind_dynamic(inner, name)
    scopes.append(inner)
    for stmt in node.body:
        _walk_stmt(stmt, scopes, emit)
    scopes.pop()


def _walk_class(node: ast.ClassDef, scopes: list[_Scope], emit: Any) -> None:
    for decorator in node.decorator_list:
        _walk_expr(decorator, scopes, emit)
    for base in node.bases:
        _walk_expr(base, scopes, emit)
    _bind_dynamic(scopes[-1], node.name)
    class_scope = _Scope()
    scopes.append(class_scope)
    for stmt in node.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.pop()
            _walk_function(stmt, scopes, emit, bind_enclosing=False)
            scopes.append(class_scope)
        else:
            _walk_stmt(stmt, scopes, emit)
    scopes.pop()


def _walk_branch(body: list[ast.stmt], scopes: list[_Scope], emit: Any,
                 before: tuple[dict[str, bool], dict[str, bool], dict[str, Any]]) -> tuple[dict[str, bool], dict[str, bool], dict[str, Any]]:
    _restore(scopes[-1], before)
    for stmt in body:
        _walk_stmt(stmt, scopes, emit)
    return _snapshot(scopes[-1])


def _walk_if(node: ast.If, scopes: list[_Scope], emit: Any) -> None:
    _walk_expr(node.test, scopes, emit)
    before = _snapshot(scopes[-1])
    after_body = _walk_branch(node.body, scopes, emit, before)
    after_else = _walk_branch(node.orelse, scopes, emit, before)
    _merge(scopes[-1], before, [after_body, after_else])


def _walk_optional_body(node: ast.For | ast.AsyncFor | ast.While, scopes: list[_Scope], emit: Any) -> None:
    """Visit a loop body, then keep only bindings that were already true before it."""
    before = _snapshot(scopes[-1])
    for stmt in node.body:
        _walk_stmt(stmt, scopes, emit)
    after = _snapshot(scopes[-1])
    _merge(scopes[-1], before, [after, before])
    for stmt in node.orelse:
        _walk_stmt(stmt, scopes, emit)


def _pattern_names(pattern: ast.AST) -> list[str]:
    names = []
    for child in ast.walk(pattern):
        if isinstance(child, ast.MatchAs) and child.name:
            names.append(child.name)
        elif isinstance(child, ast.MatchStar) and child.name:
            names.append(child.name)
        elif isinstance(child, ast.MatchMapping) and child.rest:
            names.append(child.rest)
    return names


def _walk_match(node: ast.Match, scopes: list[_Scope], emit: Any) -> None:
    _walk_expr(node.subject, scopes, emit)
    before = _snapshot(scopes[-1])
    snaps = []
    for case in node.cases:
        _restore(scopes[-1], before)
        for name in _pattern_names(case.pattern):
            _bind_dynamic(scopes[-1], name)
        if case.guard:
            _walk_expr(case.guard, scopes, emit)
        for stmt in case.body:
            _walk_stmt(stmt, scopes, emit)
        snaps.append(_snapshot(scopes[-1]))
    _merge(scopes[-1], before, snaps or [before])


def _walk_stmt(stmt: ast.stmt, scopes: list[_Scope], emit: Any) -> None:
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        _walk_function(stmt, scopes, emit)
    elif isinstance(stmt, ast.ClassDef):
        _walk_class(stmt, scopes, emit)
    elif isinstance(stmt, ast.Assign):
        _walk_expr(stmt.value, scopes, emit)
        for target in stmt.targets:
            _bind_target(target, stmt.value, scopes, emit)
    elif isinstance(stmt, ast.AnnAssign):
        _walk_expr(stmt.annotation, scopes, emit)
        if stmt.value is not None:
            _walk_expr(stmt.value, scopes, emit)
            _bind_target(stmt.target, stmt.value, scopes, emit)
        else:
            _bind_target(stmt.target, None, scopes, emit)
    elif isinstance(stmt, ast.AugAssign):
        _walk_expr(stmt.value, scopes, emit)
        if isinstance(stmt.target, ast.Name):
            _bind_dynamic(scopes[-1], stmt.target.id)
        else:
            _walk_expr(stmt.target, scopes, emit)
    elif isinstance(stmt, ast.Delete):
        for target in stmt.targets:
            _bind_target(target, None, scopes, emit)
    elif isinstance(stmt, (ast.Import,)):
        _bind_import(scopes[-1], stmt)
    elif isinstance(stmt, ast.ImportFrom):
        _bind_import_from(scopes[-1], stmt)
    elif isinstance(stmt, (ast.Global, ast.Nonlocal)):
        for name in stmt.names:
            _bind_dynamic(scopes[-1], name)
    elif isinstance(stmt, ast.If):
        _walk_if(stmt, scopes, emit)
    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
        _walk_expr(stmt.iter, scopes, emit)
        _bind_target(stmt.target, None, scopes, emit)
        _walk_optional_body(stmt, scopes, emit)
    elif isinstance(stmt, ast.While):
        _walk_expr(stmt.test, scopes, emit)
        _walk_optional_body(stmt, scopes, emit)
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            _walk_expr(item.context_expr, scopes, emit)
            if item.optional_vars is not None:
                _bind_target(item.optional_vars, item.context_expr, scopes, emit)
        for child in stmt.body:
            _walk_stmt(child, scopes, emit)
    elif isinstance(stmt, _TRY_TYPES):
        for child in stmt.body:
            _walk_stmt(child, scopes, emit)
        for handler in stmt.handlers:
            _walk_expr(handler.type, scopes, emit)
            scopes.append(_Scope())
            if handler.name:
                _bind_dynamic(scopes[-1], handler.name)
            for child in handler.body:
                _walk_stmt(child, scopes, emit)
            scopes.pop()
        for child in stmt.orelse + stmt.finalbody:
            _walk_stmt(child, scopes, emit)
    elif _MATCH is not None and isinstance(stmt, _MATCH):
        _walk_match(stmt, scopes, emit)
    elif isinstance(stmt, ast.Expr):
        _walk_expr(stmt.value, scopes, emit)
    elif isinstance(stmt, (ast.Return, ast.Raise, ast.Assert)):
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr):
                _walk_expr(child, scopes, emit)
    else:
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                _walk_stmt(child, scopes, emit)
            elif isinstance(child, ast.expr):
                _walk_expr(child, scopes, emit)


def check_python_aead_nonces(source: str, file_label: str) -> list[dict[str, Any]]:
    """Flag statically fixed nonces passed to recognized AEAD encrypt calls."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    findings: list[dict[str, Any]] = []
    lines = source.splitlines()
    source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
    module = _Scope()
    for name in _AEAD:
        module.constructors[name] = True
    scopes = [module]

    def emit(node: ast.Call) -> None:
        rule = "CRYPTO-AEAD-STATIC-NONCE"
        line = lines[node.lineno - 1]
        column = len(line.encode("utf-8")[:node.col_offset].decode("utf-8")) + 1
        target = f"{file_label}:{node.lineno}:{column}"
        findings.append({
            "id": hashlib.sha256((rule + "|" + target).encode()).hexdigest()[:10].upper(),
            "rule": rule,
            "target": target,
            "title": "Statically fixed AEAD encryption nonce",
            "priority": "review",
            "status": "UNCONFIRMED — needs owner validation",
            "evidence_class": "static_code_finding",
            "taxonomy": classify(rule),
            "evidence": {"file": file_label, "line": node.lineno, "column": column,
                         "source_sha256": source_sha256,
                         "nonce_class": "syntactically fixed"},
            "remediation": "Ensure nonce uniqueness for every encryption under the same key; use a verified nonce-management design.",
            "validation_needed": "Owner must verify runtime nonce generation, key lifecycle, and whether the encrypt call is reachable.",
        })

    for stmt in tree.body:
        _walk_stmt(stmt, scopes, emit)
    return findings
