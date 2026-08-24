"""Locate and analyze the function definition enclosing a Finding.

v0.1.0 scope guard: only importable, module-level function definitions are
supported. Methods, nested functions, and module top-level code are reported
as `unsupported` and left for manual triage rather than force-fitting a
harness onto them.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from secfix.findings import Finding


@dataclass
class UnsupportedTarget:
    kind: str = "unsupported"
    reason: str = ""


@dataclass
class HarnessTarget:
    kind: str = "supported"
    module_import_path: str = ""
    function_name: str = ""
    param_names: list[str] = None
    tainted_param: str = ""
    tainted_param_assumed: bool = False
    source_file: Path = None
    lineno: int = 0
    end_lineno: int = 0
    # How the function obtains its DB handle:
    #   "param"          -> db_access_name is a parameter that takes the mock connection
    #   "module_getter"  -> db_access_name is a module-level callable to monkeypatch
    #   "module_attr"    -> db_access_name is a module-level object (e.g. Django's
    #                       `connection`) whose .cursor() is called directly; monkeypatch
    #                       the object itself, not a getter function
    #   "unknown"        -> could not determine; harness should skip
    db_access_kind: str = "unknown"
    db_access_name: str = ""
    # Required params (no default in the signature) other than the tainted
    # param and any db-access param, mapped to a benign literal source string
    # to embed in the generated harness. A value of None means "unknown type,
    # cannot default" -> the harness must skip.
    benign_defaults: dict = None
    # Dotted settings module (e.g. "pygoat.settings") if repo_root looks like
    # a Django project (has a top-level manage.py naming one), else None. When
    # set, the harness must call django.setup() against it before importing
    # the flagged module.
    django_settings_module: Optional[str] = None
    # Set when the tainted param is a Django request object and the taint
    # enters through request.POST/GET/FILES rather than the param itself
    # being the tainted value. {"request_param": "request", "dict_name":
    # "POST", "key": "name"}. When set, the harness must build a real
    # HttpRequest (e.g. via django.test.RequestFactory) with SENTINEL under
    # that key, instead of passing SENTINEL as the param value directly.
    request_taint: Optional[dict] = None


class _EnclosingFinder(ast.NodeVisitor):
    """Walks the module tree tracking ancestry so we can determine, for the
    function that encloses the finding's lines, whether it is nested inside
    a class or another function.
    """

    def __init__(self, start_line: int, end_line: int):
        self.start_line = start_line
        self.end_line = end_line
        self.stack: list[ast.AST] = []
        self.match_node: Optional[ast.FunctionDef | ast.AsyncFunctionDef] = None
        self.match_ancestors: list[ast.AST] = []

    def _contains(self, node: ast.AST) -> bool:
        node_end = getattr(node, "end_lineno", node.lineno)
        return node.lineno <= self.start_line and self.end_line <= node_end

    def _visit_def(self, node):
        if self._contains(node):
            # Prefer the innermost enclosing def, so keep descending and let
            # a nested match overwrite this one.
            self.match_node = node
            self.match_ancestors = list(self.stack)
        self.stack.append(node)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_def(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_def(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.stack.append(node)
        self.generic_visit(node)
        self.stack.pop()


_REQUEST_DATA_DICTS = {"POST", "GET", "FILES"}


def _string_const(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _detect_request_taint(
    func: ast.FunctionDef, span_start: int, span_end: int
) -> Optional[dict]:
    """Detect the Django-view shape: taint enters via request.POST/GET/FILES
    rather than through a scalar parameter directly. Narrow by design (v0.1.0
    spike) - only matches a parameter literally named 'request' (the Django
    convention for the first positional arg of a view), and only a direct
    `.get('key')` call or `['key']` subscript on one of the three request
    data dicts, within the finding span. Anything more indirect (taint
    reaching the sink through a variable assigned from request data
    elsewhere in the function, a custom request-like wrapper, etc.) is not
    detected and falls back to the scalar-param guess, which will likely
    crash the harness - that's a real limit, not silently papered over.
    """
    param_names = {a.arg for a in func.args.args}
    if "request" not in param_names:
        return None

    for node in ast.walk(func):
        lineno = getattr(node, "lineno", None)
        if lineno is None or not (span_start <= lineno <= span_end):
            continue

        # request.POST.get('key', ...)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr in _REQUEST_DATA_DICTS
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "request"
            and node.args
        ):
            key = _string_const(node.args[0])
            if key is not None:
                return {"request_param": "request", "dict_name": node.func.value.attr, "key": key}

        # request.POST['key']
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr in _REQUEST_DATA_DICTS
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "request"
        ):
            slice_node = node.slice
            # Python <3.9 wraps the subscript key in ast.Index.
            if isinstance(slice_node, ast.Index):
                slice_node = slice_node.value
            key = _string_const(slice_node)
            if key is not None:
                return {"request_param": "request", "dict_name": node.value.attr, "key": key}

    return None


def _guess_tainted_param(
    func: ast.FunctionDef, span_start: int, span_end: int
) -> tuple[str, bool]:
    param_names = [a.arg for a in func.args.args]
    if not param_names:
        return "", False

    # Look for a parameter name referenced as a bare Name within the finding
    # span; if exactly one param matches, that's almost certainly the taint
    # source that reached the sink.
    referenced: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and node.id in param_names:
            lineno = getattr(node, "lineno", None)
            if lineno is not None and span_start <= lineno <= span_end:
                referenced.add(node.id)

    candidates = [p for p in param_names if p in referenced]
    if len(candidates) == 1:
        return candidates[0], False

    # Fall back: first str-typed-or-unannotated parameter, flagged as assumed.
    for arg in func.args.args:
        if arg.annotation is None:
            return arg.arg, True
        if isinstance(arg.annotation, ast.Name) and arg.annotation.id == "str":
            return arg.arg, True

    return param_names[0], True


CONN_PARAM_NAMES = {"conn", "connection", "cursor", "cur", "db"}
CONN_GETTER_NAMES = {"get_connection", "get_conn", "get_db", "get_db_connection", "connect"}
# e.g. Django's `from django.db import connection; connection.cursor()` —
# the module-level object itself is the connection, not a getter function
# that returns one. Kept narrow to .cursor() specifically (v0.1.0 spike,
# added for django.nV's finding) rather than a broader attribute-call
# heuristic that would risk false-matching unrelated methods.
CONN_ATTR_METHODS = {"cursor"}


def _guess_db_access(func: ast.FunctionDef) -> tuple[str, str]:
    param_names = [a.arg for a in func.args.args]
    for name in param_names:
        if name in CONN_PARAM_NAMES:
            return "param", name

    for node in ast.walk(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in CONN_GETTER_NAMES:
                return "module_getter", node.func.id

    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in CONN_ATTR_METHODS
            and isinstance(node.func.value, ast.Name)
        ):
            return "module_attr", node.func.value.id

    return "unknown", ""


def _benign_default_literal(arg: ast.arg) -> Optional[str]:
    """Return a Python source literal to use as a benign default for a
    required parameter, or None if the type can't be safely guessed.
    """
    if arg.annotation is None:
        return "'test_value'"
    if isinstance(arg.annotation, ast.Name):
        mapping = {
            "str": "'test_value'",
            "int": "0",
            "float": "0.0",
            "bool": "False",
            "list": "[]",
            "dict": "{}",
            "List": "[]",
            "Dict": "{}",
        }
        return mapping.get(arg.annotation.id)
    return None


def _compute_benign_defaults(
    func: ast.FunctionDef, tainted_param: str, db_access_kind: str, db_access_name: str
) -> dict:
    args = func.args.args
    num_defaults = len(func.args.defaults)
    required_args = args[: len(args) - num_defaults] if num_defaults else args

    defaults: dict = {}
    for arg in required_args:
        if arg.arg == tainted_param:
            continue
        if db_access_kind == "param" and arg.arg == db_access_name:
            continue
        defaults[arg.arg] = _benign_default_literal(arg)

    return defaults


def analyze_finding(finding: Finding, repo_root: Path) -> "UnsupportedTarget | HarnessTarget":
    full_path = repo_root / finding.file_path
    source = full_path.read_text()
    tree = ast.parse(source, filename=str(full_path))

    finder = _EnclosingFinder(finding.start_line, finding.end_line)
    finder.visit(tree)

    if finder.match_node is None:
        return UnsupportedTarget(
            reason="finding is at module top-level, not inside a function"
        )

    if any(isinstance(a, ast.ClassDef) for a in finder.match_ancestors):
        return UnsupportedTarget(
            reason="enclosing definition is a method inside a class, not a module-level function"
        )

    if any(
        isinstance(a, (ast.FunctionDef, ast.AsyncFunctionDef))
        for a in finder.match_ancestors
    ):
        return UnsupportedTarget(
            reason="enclosing definition is a nested function, not importable at module level"
        )

    func = finder.match_node
    if isinstance(func, ast.AsyncFunctionDef):
        return UnsupportedTarget(
            reason="enclosing definition is an async function, not supported in v0.1.0"
        )

    param_names = [a.arg for a in func.args.args]
    request_taint = _detect_request_taint(func, finding.start_line, finding.end_line)
    if request_taint is not None:
        tainted_param, assumed = request_taint["request_param"], False
    else:
        tainted_param, assumed = _guess_tainted_param(func, finding.start_line, finding.end_line)
    db_access_kind, db_access_name = _guess_db_access(func)
    benign_defaults = _compute_benign_defaults(func, tainted_param, db_access_kind, db_access_name)

    return HarnessTarget(
        module_import_path=_dotted_path(finding.file_path),
        function_name=func.name,
        param_names=param_names,
        tainted_param=tainted_param,
        tainted_param_assumed=assumed,
        source_file=full_path,
        lineno=func.lineno,
        end_lineno=getattr(func, "end_lineno", func.lineno),
        db_access_kind=db_access_kind,
        db_access_name=db_access_name,
        benign_defaults=benign_defaults,
        django_settings_module=_detect_django_settings_module(repo_root),
        request_taint=request_taint,
    )


def _dotted_path(rel_path: Path) -> str:
    parts = list(Path(rel_path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


_DJANGO_SETTINGS_RE = re.compile(
    r"""DJANGO_SETTINGS_MODULE['"]\s*,\s*['"]([\w.]+)['"]"""
)


def _detect_django_settings_module(repo_root: Path) -> Optional[str]:
    """v0.1.0 Django detection: a top-level manage.py that calls
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', '<module>') is treated as
    proof the target is a Django project, and that string is the settings
    module the harness must set up against. No manage.py, or a manage.py that
    doesn't spell this out in the conventional django-admin-generated form,
    means "not detected" rather than a guess.
    """
    manage_py = repo_root / "manage.py"
    if not manage_py.exists():
        return None
    match = _DJANGO_SETTINGS_RE.search(manage_py.read_text())
    return match.group(1) if match else None
