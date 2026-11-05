"""Offline AST review leads; no source execution or input-flow claims.

Resolve unambiguous imports within lexical scopes. Rebound names are deliberately
ignored rather than assumed to retain an imported or builtin identity.
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any

from decrypto_taxonomy import classify

RULES = {
    'PY-UNSAFE-DESERIALIZATION': (
        'Object deserialization requires trusted input',
        'Use a data-only format for untrusted input; authenticate and constrain any required serialized objects.'),
    'PY-UNSAFE-YAML': (
        'YAML loader safety requires review',
        'Use yaml.safe_load/safe_load_all or an explicit SafeLoader for untrusted YAML.'),
    'PY-SHELL-EXECUTION': (
        'Shell command execution requires input review',
        'Prefer an argument list with shell=False and validate executable and arguments.'),
    'PY-DYNAMIC-EVALUATION': (
        'Dynamic Python evaluation requires input review',
        'Avoid evaluating untrusted text; use a constrained data parser or explicit operation dispatch.'),
}


class Bindings(ast.NodeVisitor):
    """Collect one scope's bindings without borrowing imports from child scopes."""
    def __init__(self):
        self.names: dict[str, str | None] = {}

    def bind(self, name, qualified=None):
        self.names[name] = qualified if name not in self.names else None

    def visit_Import(self, node):
        for item in node.names:
            self.bind(item.asname or item.name.split('.')[0],
                      item.name if item.asname else item.name.split('.')[0])

    def visit_ImportFrom(self, node):
        for item in node.names:
            if item.name == '*':
                continue
            self.bind(item.asname or item.name,
                      f'{node.module}.{item.name}' if node.module and not node.level else None)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node.id)

    def visit_FunctionDef(self, node):
        self.bind(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node):
        pass

    def visit_ExceptHandler(self, node):
        if node.name:
            self.bind(node.name)
        self.generic_visit(node)


def check_python_security(source: str, file_label: str) -> list[dict[str, Any]]:
    tree = ast.parse(source)
    lines = source.splitlines()
    source_hash = hashlib.sha256(source.encode('utf-8')).hexdigest()
    findings = []

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.scopes = []

        def scope(self, node, body):
            bindings = Bindings()
            for item in body:
                bindings.visit(item)
            args = getattr(node, 'args', None)
            if args:
                for arg in args.posonlyargs + args.args + args.kwonlyargs:
                    bindings.bind(arg.arg)
                for arg in (args.vararg, args.kwarg):
                    if arg:
                        bindings.bind(arg.arg)
            self.scopes.append(bindings.names)
            for item in body:
                self.visit(item)
            self.scopes.pop()

        def visit_Module(self, node):
            self.scope(node, node.body)

        def visit_FunctionDef(self, node):
            # Defaults and decorators execute in the enclosing scope.
            for item in node.decorator_list + node.args.defaults + [x for x in node.args.kw_defaults if x]:
                self.visit(item)
            self.scope(node, node.body)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            # Class/method binding rules need separate treatment; omit these
            # rather than apply function-scope resolution incorrectly.
            pass

        def visit_Lambda(self, node):
            self.scope(node, [node.body])

        def visit_ListComp(self, node):
            # Comprehension scopes are outside this narrow resolver.
            pass

        visit_SetComp = visit_ListComp
        visit_DictComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp

        def qualified(self, node):
            if isinstance(node, ast.Name):
                for scope in reversed(self.scopes):
                    if node.id in scope:
                        return scope[node.id] or ''
                return 'builtins.' + node.id if node.id in ('eval', 'exec') else ''
            if isinstance(node, ast.Attribute):
                parent = self.qualified(node.value)
                return parent + '.' + node.attr if parent else ''
            return ''

        def visit_Call(self, node):
            name = self.qualified(node.func)
            rule = None
            if name in ('pickle.load', 'pickle.loads', '_pickle.load', '_pickle.loads',
                        'dill.load', 'dill.loads'):
                rule = 'PY-UNSAFE-DESERIALIZATION'
            elif name in ('yaml.unsafe_load', 'yaml.unsafe_load_all'):
                rule = 'PY-UNSAFE-YAML'
            elif name in ('yaml.load', 'yaml.load_all'):
                loader = next((k.value for k in node.keywords if k.arg == 'Loader'),
                              node.args[1] if len(node.args) > 1 else None)
                if self.qualified(loader) not in ('yaml.SafeLoader', 'yaml.CSafeLoader'):
                    rule = 'PY-UNSAFE-YAML'
            elif name in ('os.system', 'os.popen', 'subprocess.getoutput', 'subprocess.getstatusoutput'):
                rule = 'PY-SHELL-EXECUTION'
            elif name in ('subprocess.run', 'subprocess.Popen', 'subprocess.call',
                          'subprocess.check_call', 'subprocess.check_output'):
                if any(k.arg == 'shell' and isinstance(k.value, ast.Constant)
                       and k.value.value is True for k in node.keywords):
                    rule = 'PY-SHELL-EXECUTION'
            elif name in ('builtins.eval', 'builtins.exec'):
                rule = 'PY-DYNAMIC-EVALUATION'
            if rule:
                column = len(lines[node.lineno - 1].encode('utf-8')[:node.col_offset].decode('utf-8')) + 1
                target = f'{file_label}:{node.lineno}:{column}'
                title, remediation = RULES[rule]
                findings.append({
                    'id': hashlib.sha256((rule + '|' + target).encode()).hexdigest()[:10].upper(),
                    'rule': rule, 'target': target, 'title': title, 'priority': 'review',
                    'status': 'UNCONFIRMED — needs owner validation',
                    'evidence_class': 'static_code_finding', 'taxonomy': classify(rule),
                    'evidence': {'file': file_label, 'line': node.lineno, 'column': column,
                                 'source_sha256': source_hash, 'recognized_api': name},
                    'remediation': remediation,
                    'validation_needed': 'Trace input provenance and runtime reachability. Trusted inputs may be intentional; API use alone does not prove a vulnerability.',
                })
            self.generic_visit(node)

    Visitor().visit(tree)
    return sorted(findings, key=lambda f: (f['evidence']['line'], f['evidence']['column'], f['rule']))
