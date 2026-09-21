"""Run pinned OpenGrep rules over executable code selected from the shared IR."""

from __future__ import annotations

import ast
import inspect
import json
import os
import re
import subprocess
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from .checks._pyast import dotted
from .checks._pyast import parse as parse_python
from .checks.code_lane import (
    _SUPPORTED_SHELL_DIALECTS,
    _governing_manifest,
    _manifest_index,
    build_code_lane,
    installer_idiom,
    own_install_path,
)
from .checks.grants import declared_capabilities, denied_capabilities, effective_grants
from .findings import Finding, cap_findings, dedupe_findings, vector_registry
from .opengrep_runtime import OpenGrepRuntimeError, resolve_opengrep

_RULES = Path(__file__).with_name("rules") / "opengrep-phase1.yml"
_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_MAX_REPORT_BYTES = 16 * 1024 * 1024
_MAX_TARGET_BYTES = 5 * 1024 * 1024
_MAX_POSTFILTERS_PER_TARGET = 32
_PY_TAINT_VECTORS = {"SXV-008", "SXV-018", "SXV-019"}
_PY_SINKS = {
    "os.system", "os.popen", "subprocess.run", "subprocess.call",
    "os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execv", "os.execve",
    "os.execvp", "os.execvpe", "os.posix_spawn", "os.posix_spawnp",
    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
    "subprocess.getoutput", "subprocess.getstatusoutput",
}
_PY_BUILTIN_SINKS = {"eval", "exec"}
_PY_CANONICAL_SINKS = _PY_SINKS | {"builtins.eval", "builtins.exec"}
_PY_FUNCTION_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_PY_COMPREHENSION_SCOPES = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_PY_SCOPES = (*_PY_FUNCTION_SCOPES, ast.ClassDef, *_PY_COMPREHENSION_SCOPES)
_UNKNOWN = object()
_SOURCE_MARKER = object()
_OTHER_MARKER = object()
_INVALID_CALL = object()


@dataclass(frozen=True)
class SelectedCode:
    rel: str
    text: str
    origin: str
    suffix: str = ".py"


_KEEP_SUFFIX = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
_LANGUAGE_KIND = {"python": ("script_python", ".py"), "shell": ("script_shell", ".sh"),
                  "javascript": ("script_javascript", ".js"),
                  "typescript": ("script_typescript", ".ts")}


def select_executable_code(
    parsed,
    code_units=None,
    *,
    languages=("python",),
) -> list[SelectedCode]:
    """Select supported code files and recognized executable instruction fences."""
    if code_units is None:
        code_units, _notes = build_code_lane(parsed)
    selected_kinds = dict(_LANGUAGE_KIND[language] for language in languages)
    selected = []
    for unit in code_units:
        if unit.kind not in selected_kinds:
            continue
        if unit.kind == "script_shell" and unit.dialect not in _SUPPORTED_SHELL_DIALECTS:
            continue
        suffix = selected_kinds[unit.kind]
        ext = os.path.splitext(unit.rel)[1].lower()
        if unit.origin == "file" and ext in _KEEP_SUFFIX:
            suffix = ext                        # OpenGrep reads JSX and TSX from the extension
        selected.append(SelectedCode(unit.rel, unit.text, unit.origin, suffix))
    return selected


def _coverage(rule: str, message: str, *, path: str = "", severity: str = "low"):
    return Finding(vector="", rule=rule, severity=severity, path=path, message=message)


def _target_name(raw_path: object) -> str:
    return str(raw_path or "").replace("\\", "/").rsplit("/", 1)[-1]


def _rule_id(raw: object) -> str:
    value = str(raw or "")
    marker = "skill-xray."
    return value[value.rfind(marker):] if marker in value else value


def _remap_engine_paths(value, targets):
    if isinstance(value, list):
        return [_remap_engine_paths(item, targets) for item in value]
    if not isinstance(value, dict):
        return value
    mapped = {}
    for key, item in value.items():
        if key == "path" and isinstance(item, str):
            target = targets.get(_target_name(item))
            mapped[key] = target.rel if target else _target_name(item)
        else:
            mapped[key] = _remap_engine_paths(item, targets)
    return mapped


def _location(result: dict, target: SelectedCode) -> tuple[int, dict] | None:
    start = result.get("start") if isinstance(result.get("start"), dict) else {}
    end = result.get("end") if isinstance(result.get("end"), dict) else {}
    line = start.get("line")
    if type(line) is not int or not 1 <= line <= target.text.count("\n") + 1:
        return None
    def _bounded(value, minimum):
        return value if type(value) is int and value >= minimum else None
    return line, {
        "start": {"line": line, "col": _bounded(start.get("col"), 1),
                  "offset": _bounded(start.get("offset"), 0)},
        "end": {"line": _bounded(end.get("line"), 1), "col": _bounded(end.get("col"), 1),
                "offset": _bounded(end.get("offset"), 0)},
    }


def _fence_region(target, parsed, start, end, source_cache):
    """Prove generated UTF-8 positions against the original, same-line Markdown.

    Markdown already extracted the code; a suffix comparison recovers only the
    removed container prefix. Tabs and transformed/ambiguous spans stay unlocated.
    """
    artifact = parsed.by_rel.get(target.rel) if parsed is not None else None
    if artifact is None or artifact.text is None:
        raise ValueError("fence source unavailable")
    key = id(target)
    if key not in source_cache:
        source_cache[key] = target.text.split("\n"), artifact.text.split("\n")
    generated, original = source_cache[key]
    positions = []
    for position in (start, end):
        if not isinstance(position, dict):
            raise ValueError("invalid fence position")
        line, col = position.get("line"), position.get("col")
        if (type(line) is not int or type(col) is not int
                or not 1 <= line <= min(len(generated), len(original))):
            raise ValueError("invalid fence position")
        encoded = generated[line - 1].encode("utf-8")
        if not 1 <= col <= len(encoded) + 1:
            raise ValueError("invalid fence column")
        positions.append((line, len(encoded[:col - 1].decode("utf-8"))))
    (first, start_char), (last, end_char) = positions
    if positions[1] < positions[0]:
        raise ValueError("inverted fence region")
    prefixes = []
    for line in range(first - 1, last):
        source, lifted = original[line], generated[line]
        if not lifted or "\t" in source or "\t" in lifted or not source.endswith(lifted):
            raise ValueError("unprovable fence prefix")
        prefixes.append(len(source) - len(lifted))
    generated_span = generated[first - 1:last]
    generated_span[-1] = generated_span[-1][:end_char]
    generated_span[0] = generated_span[0][start_char:]
    original_span = original[first - 1:last]
    original_span[-1] = original_span[-1][:prefixes[-1] + end_char]
    original_span[0] = original_span[0][prefixes[0] + start_char:]
    if original_span != generated_span:
        raise ValueError("fence span crosses transformed source")
    return {
        "start": {"line": first, "col": start["col"]
                  + len(original[first - 1][:prefixes[0]].encode("utf-8"))},
        "end": {"line": last, "col": end["col"]
                + len(original[last - 1][:prefixes[-1]].encode("utf-8"))},
    }


def _fence_trace(value, targets, parsed, source_cache):
    """Map only locations belonging to known generated fence targets."""
    if isinstance(value, list):
        return [_fence_trace(item, targets, parsed, source_cache) for item in value]
    if not isinstance(value, dict):
        return value
    mapped = {key: _fence_trace(item, targets, parsed, source_cache)
              for key, item in value.items()}
    if "path" in value and "start" in value and "end" in value:
        target = targets.get(_target_name(value["path"]))
        if target is None:
            raise ValueError("unknown trace target")
        if target.origin == "fence":
            mapped.update(_fence_region(target, parsed, value["start"], value["end"], source_cache))
    return mapped


def _map_fence_evidence(evidence, target, targets, parsed, trace, source_cache):
    """Reporting-only remapping, called after generated-code detection/postfilters."""
    evidence["engine_location"] = deepcopy({key: evidence[key] for key in ("start", "end")})
    try:
        evidence.update(_fence_region(
            target, parsed, evidence["start"], evidence["end"], source_cache))
        evidence["location_mapping"] = "validated"
    except (ValueError, TypeError, AttributeError):
        evidence["location_mapping"] = "unvalidated"
    if trace:
        evidence["engine_dataflow_trace"] = deepcopy(evidence["dataflow_trace"])
        try:
            evidence["dataflow_trace"] = _remap_engine_paths(
                _fence_trace(trace, targets, parsed, source_cache), targets)
            evidence["trace_mapping"] = "validated"
        except (ValueError, TypeError, AttributeError):
            evidence["trace_mapping"] = "unvalidated"


def _scope_chain(tree: ast.Module, line: int, col: int | None = None):
    scopes = [
        node for node in ast.walk(tree)
        if isinstance(node, _PY_SCOPES)
        and node.lineno <= line <= (node.end_lineno or node.lineno)
        and (col is None or _contains_position(node, line, col))
    ]
    scopes.sort(key=lambda node: (node.lineno, -(node.end_lineno or 0)))
    return [tree, *(
        scope for index, scope in enumerate(scopes)
        if not isinstance(scope, ast.ClassDef)
        or not any(isinstance(inner, _PY_FUNCTION_SCOPES) for inner in scopes[index + 1:])
    )]


def _scope_nodes(scope):
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _PY_SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def _import_binding(node, name: str):
    if isinstance(node, ast.Import):
        for alias in reversed(node.names):
            bound = alias.asname or alias.name.split(".", 1)[0]
            if bound == name:
                return "import", alias.name if alias.asname else alias.name.split(".", 1)[0]
    elif isinstance(node, ast.ImportFrom):
        for alias in reversed(node.names):
            if alias.name != "*" and (alias.asname or alias.name) == name:
                origin = "." * node.level + (
                    "%s.%s" % (node.module, alias.name) if node.module else alias.name
                )
                return "import", origin
    return None


def _target_binds(node, name: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id == name
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_target_binds(item, name) for item in node.elts)
    return isinstance(node, ast.Starred) and _target_binds(node.value, name)


def _statement_binding(node, name: str):
    imported = _import_binding(node, name)
    if imported:
        return imported
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return ("other", None) if node.name == name else None
    targets = []
    if isinstance(node, ast.Assign):
        if any(_target_binds(target, name) for target in node.targets):
            sink = dotted(node.value)
            if sink in _PY_SINKS:
                return "sink", sink
        targets = node.targets
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        targets = [node.target]
    elif isinstance(node, ast.AugAssign):
        targets = [node.target]
    elif isinstance(node, ast.Delete):
        return ("delete", None) if any(
            _target_binds(target, name) for target in node.targets
        ) else None
    return ("other", None) if any(_target_binds(target, name) for target in targets) else None


def _preserves_name_binding(node, name: str) -> bool:
    if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
        return False
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return dotted(node.value) == name and any(_target_binds(target, name) for target in targets)


def _before(node, line: int, col: int | None) -> bool:
    end_line = node.end_lineno or node.lineno
    return end_line < line or (
        end_line == line and col is not None and (node.end_col_offset or 0) < col
    )


def _last_binding(scope, name: str, line: int, col: int | None):
    # ponytail: branch-local bindings fail open; widen only with a control-flow proof.
    binding = None
    if isinstance(scope, _PY_FUNCTION_SCOPES):
        arguments = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
        arguments.extend(arg for arg in (scope.args.vararg, scope.args.kwarg) if arg)
        if any(arg.arg == name for arg in arguments):
            binding = ("other", None)
    if isinstance(scope, _PY_COMPREHENSION_SCOPES) and any(
        _target_binds(generator.target, name) for generator in scope.generators
    ):
        binding = ("other", None)
    body = getattr(scope, "body", ())
    if not isinstance(body, list):
        return binding
    for statement in body:
        if isinstance(statement, ast.stmt) and _before(statement, line, col):
            if not _preserves_name_binding(statement, name):
                binding = _statement_binding(statement, name) or binding
    return binding


def _static_value(node, values):
    if isinstance(node, ast.Name):
        return values.get(node.id, _UNKNOWN)
    if isinstance(node, ast.Dict):
        keys = [_static_value(item, values) for item in node.keys]
        items = [_static_value(item, values) for item in node.values]
        if any(item is _UNKNOWN for item in (*keys, *items)):
            return _UNKNOWN
        try:
            return dict(zip(keys, items, strict=True))
        except (TypeError, ValueError):
            return _UNKNOWN
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_static_value(item, values) for item in node.elts]
        if any(item is _UNKNOWN for item in items):
            return _UNKNOWN
        constructor = {ast.List: list, ast.Tuple: tuple, ast.Set: set}[type(node)]
        try:
            return constructor(items)
        except TypeError:
            return _UNKNOWN
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = _static_value(node.operand, values)
        return not value if value is not _UNKNOWN else _UNKNOWN
    if isinstance(node, ast.BoolOp):
        result = _static_value(node.values[0], values)
        for item in node.values[1:]:
            if result is _UNKNOWN:
                return _UNKNOWN
            if isinstance(node.op, ast.And) and not result:
                return result
            if isinstance(node.op, ast.Or) and result:
                return result
            result = _static_value(item, values)
        return result
    if isinstance(node, ast.Compare):
        left = _static_value(node.left, values)
        rights = [_static_value(item, values) for item in node.comparators]
        if left is _UNKNOWN or any(item is _UNKNOWN for item in rights):
            return _UNKNOWN
        operations = {
            ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b,
            ast.Is: lambda a, b: a is b, ast.IsNot: lambda a, b: a is not b,
            ast.Lt: lambda a, b: a < b, ast.LtE: lambda a, b: a <= b,
            ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
            ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
        }
        try:
            for operation, right in zip(node.ops, rights, strict=True):
                if not operations[type(operation)](left, right):
                    return False
                left = right
            return True
        except (KeyError, TypeError, ValueError):
            return _UNKNOWN
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left, right = _static_value(node.left, values), _static_value(node.right, values)
        return left | right if isinstance(left, dict) and isinstance(right, dict) else _UNKNOWN
    if isinstance(node, ast.Subscript):
        owner, key = _static_value(node.value, values), _static_value(node.slice, values)
        if owner is _UNKNOWN or key is _UNKNOWN:
            return _UNKNOWN
        try:
            return owner[key]
        except (KeyError, IndexError, TypeError):
            return _UNKNOWN
    if isinstance(node, ast.Call):
        call = dotted(node.func)
        if call == "dict" and values.get("dict", None) is not _UNKNOWN:
            if len(node.args) > 1 or any(item.arg is None for item in node.keywords):
                return _UNKNOWN
            try:
                result = dict(_static_value(node.args[0], values)) if node.args else {}
            except (TypeError, ValueError):
                return _UNKNOWN
            for item in node.keywords:
                value = _static_value(item.value, values)
                if value is _UNKNOWN:
                    return _UNKNOWN
                result[item.arg] = value
            return result
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            if not 1 <= len(node.args) <= 2 or node.keywords:
                return _UNKNOWN
            owner = _static_value(node.func.value, values)
            key = _static_value(node.args[0], values) if node.args else _UNKNOWN
            default = (_static_value(node.args[1], values) if len(node.args) > 1 else None)
            if (not isinstance(owner, dict) or key is _UNKNOWN
                    or len(node.args) > 1 and default is _UNKNOWN):
                return _UNKNOWN
            return owner.get(key, default)
        return _UNKNOWN
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, MemoryError, RecursionError):
        return _UNKNOWN


def _assign_static(target, value, values):
    if isinstance(target, ast.Name):
        values[target.id] = value
    elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
        owner = values.get(target.value.id, _UNKNOWN)
        key = _static_value(target.slice, values)
        item = dict(owner) if isinstance(owner, dict) else None
        if item is not None and key is not _UNKNOWN and value is not _UNKNOWN:
            item[key] = value
            values[target.value.id] = item
        else:
            values[target.value.id] = _UNKNOWN


def _apply_static(statement, values):
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        values[statement.name] = _UNKNOWN
    elif isinstance(statement, ast.Assign):
        value = _static_value(statement.value, values)
        for target in statement.targets:
            _assign_static(target, value, values)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        _assign_static(statement.target, _static_value(statement.value, values), values)
    elif isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name):
        left, right = values.get(statement.target.id, _UNKNOWN), _static_value(
            statement.value, values
        )
        values[statement.target.id] = (
            left | right
            if isinstance(statement.op, ast.BitOr)
            and isinstance(left, dict)
            and isinstance(right, dict)
            else _UNKNOWN
        )
    elif isinstance(statement, (ast.Import, ast.ImportFrom)):
        for alias in statement.names:
            values[alias.asname or alias.name.split(".", 1)[0]] = _UNKNOWN
    elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        call = statement.value
        if (isinstance(call.func, ast.Attribute) and call.func.attr == "update"
                and isinstance(call.func.value, ast.Name)):
            name = call.func.value.id
            owner = values.get(name, _UNKNOWN)
            additions = _static_value(
                ast.Call(
                    func=ast.Name(id="dict", ctx=ast.Load()),
                    args=call.args,
                    keywords=call.keywords,
                ),
                values,
            )
            values[name] = {**owner, **additions} if (
                isinstance(owner, dict) and isinstance(additions, dict)
            ) else _UNKNOWN


def _static_values_at(tree: ast.Module, line: int, col: int | None):
    values = {}
    scopes = _scope_chain(tree, line, col)
    for index, scope in enumerate(scopes):
        if isinstance(scope, _PY_FUNCTION_SCOPES):
            arguments = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            arguments.extend(arg for arg in (scope.args.vararg, scope.args.kwarg) if arg)
            values.update((arg.arg, _UNKNOWN) for arg in arguments)
        elif isinstance(scope, _PY_COMPREHENSION_SCOPES):
            values.update(
                (node.id, _UNKNOWN)
                for generator in scope.generators
                for node in ast.walk(generator.target)
                if isinstance(node, ast.Name)
            )
        limit = scopes[index + 1].lineno if index + 1 < len(scopes) else line
        body = getattr(scope, "body", ())
        if not isinstance(body, list):
            continue
        for statement in body:
            if not isinstance(statement, ast.stmt) or not _before(statement, limit, col):
                continue
            _apply_static(statement, values)
    return values


def _contains_position(node, line: int, col: int | None) -> bool:
    if not (node.lineno <= line <= (node.end_lineno or node.lineno)):
        return False
    if type(col) is not int or col < 1:
        return True
    point = col - 1
    return (line != node.lineno or point >= node.col_offset) and (
        line != node.end_lineno or point <= (node.end_col_offset or point)
    )


def _subprocess_shell_status(
    tree: ast.Module, line: int, col: int | None,
) -> tuple[bool | None, bool]:
    scopes = _scope_chain(tree, line, col)
    values = _static_values_at(tree, line, col)
    for node in ast.walk(scopes[-1]):
        if not isinstance(node, ast.Call) or not _contains_position(node, line, col):
            continue
        call = dotted(node.func)
        if not call:
            continue
        name, separator, tail = call.partition(".")
        suffix = separator + tail
        if not _has_sink_import(scopes, name, suffix, line, col) or (
            name + suffix not in _PY_SINKS and suffix.rsplit(".", 1)[-1]
            not in {"run", "call", "check_call", "check_output", "Popen"}
        ):
            continue
        shell = next((item for item in node.keywords if item.arg == "shell"), None)
        if shell is not None:
            if isinstance(shell.value, ast.Subscript):
                owner = _static_value(shell.value.value, values)
                key = _static_value(shell.value.slice, values)
                if owner is not _UNKNOWN and key is not _UNKNOWN:
                    try:
                        owner[key]
                    except (KeyError, IndexError, TypeError):
                        return False, True
            value = _static_value(shell.value, values)
            return (None if value is _UNKNOWN else bool(value)), True
        mappings = [
            _static_value(item.value, values)
            for item in node.keywords if item.arg is None
        ]
        if mappings:
            if any(mapping is _UNKNOWN for mapping in mappings):
                return None, False
            return any(
                isinstance(mapping, dict)
                and "shell" in mapping
                and bool(mapping["shell"])
                for mapping in mappings
            ), False
        return True, False
    return True, False


def _parents(tree: ast.Module):
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def _ancestor(node, parents, kinds):
    while node in parents:
        node = parents[node]
        if isinstance(node, kinds):
            return node
    return None


def _function_at(tree: ast.Module, line: int):
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    return min(functions, key=lambda node: node.end_lineno - node.lineno) if functions else None


def _source_expression(node) -> bool:
    for item in ast.walk(node):
        call = dotted(item.func) if isinstance(item, ast.Call) else None
        value = dotted(item)
        if call in {"input", "raw_input", "os.getenv"} or (
            call and call.startswith(("requests.", "httpx.", "urllib.request.urlopen"))
        ) or value and value.startswith(("sys.argv", "sys.stdin", "os.environ")):
            return True
    return False


def _argument_marker(node):
    if isinstance(node, ast.Dict):
        output = {}
        for key, value in zip(node.keys, node.values, strict=True):
            try:
                key = ast.literal_eval(key)
            except (ValueError, TypeError):
                return _UNKNOWN
            try:
                output[key] = _argument_marker(value)
            except TypeError:
                return _UNKNOWN
        return output
    if isinstance(node, (ast.List, ast.Tuple)):
        constructor = list if isinstance(node, ast.List) else tuple
        return constructor(_argument_marker(item) for item in node.elts)
    return _SOURCE_MARKER if _source_expression(node) else _OTHER_MARKER


def _signature(function, *, bound_method=False):
    arguments = function.args
    positional = [*arguments.posonlyargs, *arguments.args]
    defaults = [inspect.Parameter.empty] * (len(positional) - len(arguments.defaults))
    defaults += [_OTHER_MARKER] * len(arguments.defaults)
    parameters = []
    for index, (argument, default) in enumerate(zip(positional, defaults, strict=True)):
        if bound_method and index == 0:
            continue
        kind = (
            inspect.Parameter.POSITIONAL_ONLY
            if index < len(arguments.posonlyargs)
            else inspect.Parameter.POSITIONAL_OR_KEYWORD
        )
        parameters.append(inspect.Parameter(argument.arg, kind, default=default))
    if arguments.vararg:
        parameters.append(inspect.Parameter(
            arguments.vararg.arg, inspect.Parameter.VAR_POSITIONAL,
        ))
    for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
        parameters.append(inspect.Parameter(
            argument.arg,
            inspect.Parameter.KEYWORD_ONLY,
            default=inspect.Parameter.empty if default is None else _OTHER_MARKER,
        ))
    if arguments.kwarg:
        parameters.append(inspect.Parameter(
            arguments.kwarg.arg, inspect.Parameter.VAR_KEYWORD,
        ))
    return inspect.Signature(parameters)


def _call_arguments(call: ast.Call):
    positional = []
    for argument in call.args:
        if isinstance(argument, ast.Starred):
            if not isinstance(argument.value, (ast.List, ast.Tuple)):
                return None
            positional.extend(_argument_marker(item) for item in argument.value.elts)
        else:
            positional.append(_argument_marker(argument))
    keywords = {}
    for argument in call.keywords:
        if argument.arg is not None:
            if argument.arg in keywords:
                return _INVALID_CALL
            keywords[argument.arg] = _argument_marker(argument.value)
            continue
        if not isinstance(argument.value, ast.Dict):
            return None
        for key, value in zip(argument.value.keys, argument.value.values, strict=True):
            try:
                name = ast.literal_eval(key)
            except (ValueError, TypeError):
                return None
            if not isinstance(name, str) or name in keywords:
                return _INVALID_CALL
            keywords[name] = _argument_marker(value)
    return positional, keywords


def _sink_argument(function, line: int):
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or not (
            node.lineno <= line <= (node.end_lineno or node.lineno)
        ):
            continue
        call = dotted(node.func)
        if call in _PY_SINKS or call in _PY_BUILTIN_SINKS:
            keyword = next((item.value for item in node.keywords if item.arg == "args"), None)
            return keyword or (node.args[0] if node.args else None)
    return None


def _bound_marker(expression, arguments):
    if isinstance(expression, ast.Name):
        return arguments.get(expression.id, _UNKNOWN)
    if isinstance(expression, ast.Subscript) and isinstance(expression.value, ast.Name):
        owner = arguments.get(expression.value.id, _UNKNOWN)
        try:
            key = ast.literal_eval(expression.slice)
            return owner[key]
        except (KeyError, IndexError, TypeError, ValueError):
            return _UNKNOWN
    markers = [
        arguments.get(item.id, _UNKNOWN)
        for item in ast.walk(expression)
        if isinstance(item, ast.Name) and item.id in arguments
    ]

    def contains(marker, expected):
        if marker is expected:
            return True
        if isinstance(marker, dict):
            return any(contains(item, expected) for item in marker.values())
        if isinstance(marker, (list, tuple)):
            return any(contains(item, expected) for item in marker)
        return False

    return _SOURCE_MARKER if any(contains(item, _SOURCE_MARKER) for item in markers) else (
        _OTHER_MARKER if markers else _UNKNOWN
    )


def _resolve_alias(function, expression, line: int):
    """Follow pure local aliases (``command = user_input``) in the function's own scope
    back to the ultimate name, so a parameter laundered through a local is still traced
    to that parameter. Only a bare ``Name = Name`` copy is followed; a wrapping call
    (``sanitize(x)``) or a non-Name reassignment stops the chain, so resolution never
    invents taint that a transform in between could have cleared."""
    seen = set()
    while isinstance(expression, ast.Name) and expression.id not in seen:
        seen.add(expression.id)
        latest = None
        for node in _scope_nodes(function):
            if (isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == expression.id
                    and (node.end_lineno or node.lineno) < line
                    and (latest is None or node.lineno > latest.lineno)):
                latest = node
        if latest is None or not isinstance(latest.value, ast.Name):
            break
        expression = latest.value
        line = latest.lineno
    return expression


def _direct_scope(function, parents):
    parent = parents.get(function)
    return (
        parent
        if isinstance(parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))
        else None
    )


def _scope_binds_name(scope, name: str) -> bool:
    nodes = list(_scope_nodes(scope))
    if any(
        isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names
        for node in nodes
    ):
        return False
    return any(
        isinstance(node, ast.arg) and node.arg == name
        or isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id == name
        or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == name
        or isinstance(node, ast.ExceptHandler) and node.name == name
        or isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == name
        or isinstance(node, ast.MatchMapping) and node.rest == name
        or _import_binding(node, name) is not None
        for node in nodes
    )


def _definition_visible(function, call, parents):
    scope = _direct_scope(function, parents)
    if scope is None:
        return False
    node = call
    crossed_function = False
    while node in parents:
        node = parents[node]
        if node is scope:
            break
        if isinstance(node, _PY_SCOPES):
            if not (isinstance(node, ast.ClassDef) and crossed_function) and (
                _scope_binds_name(node, function.name)
            ):
                return False
            crossed_function |= isinstance(node, _PY_FUNCTION_SCOPES)
    else:
        return False
    current = None
    for statement in scope.body:
        if not _before(statement, call.lineno, call.col_offset + 1):
            continue
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if statement.name == function.name:
                current = statement
        elif (_statement_binding(statement, function.name)
              and not _preserves_name_binding(statement, function.name)):
            current = None
    return current is function


def _method_call_owner(function, call, parents):
    owner = parents.get(function)
    if not isinstance(owner, ast.ClassDef) or not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == function.name
        and isinstance(call.func.value, ast.Call)
        and isinstance(call.func.value.func, ast.Name)
        and call.func.value.func.id == owner.name
    ):
        return None
    return owner


def _call_flow_is_impossible(
    tree: ast.Module, source_line: int | None, sink_line: int,
    source_col: int | None = None,
):
    if source_line is None:
        return False
    function = _function_at(tree, sink_line)
    if function is None:
        return False
    parents = _parents(tree)
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _contains_position(node, source_line, source_col)
        and (
            isinstance(node.func, ast.Name) and node.func.id == function.name
            or _method_call_owner(function, node, parents) is not None
        )
    ]
    if not calls:
        return False
    sink = _sink_argument(function, sink_line)
    if sink is not None:
        sink = _resolve_alias(function, sink, sink_line)
    for call in calls:
        owner = _method_call_owner(function, call, parents)
        if owner is None and not _definition_visible(function, call, parents):
            continue
        if owner is not None and not _definition_visible(owner, call, parents):
            continue
        supplied = _call_arguments(call)
        if supplied is _INVALID_CALL:
            continue
        if supplied is None:
            return False
        try:
            bound = _signature(function, bound_method=owner is not None).bind(
                *supplied[0], **supplied[1]
            )
        except TypeError:
            continue
        if sink is None or _bound_marker(sink, bound.arguments) is _SOURCE_MARKER:
            return False
    return True


def _receiver_flow_is_impossible(tree: ast.Module, line: int):
    function = _function_at(tree, line)
    if function is None:
        return False
    parents = _parents(tree)
    if not isinstance(parents.get(function), ast.ClassDef):
        return False
    receiver_calls = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and node.lineno <= line <= (node.end_lineno or node.lineno)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"self", "cls"}
    ]
    if not receiver_calls:
        return False
    receiver = receiver_calls[0].func.value.id
    positional = [*function.args.posonlyargs, *function.args.args]
    decorators = {dotted(item) for item in function.decorator_list}
    if not positional or positional[0].arg != receiver or "staticmethod" in decorators:
        return True
    for node in _scope_nodes(function):
        if getattr(node, "lineno", line) >= line:
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id == receiver:
            return True
        if isinstance(node, ast.MatchAs) and node.name == receiver:
            return True
        if isinstance(node, ast.alias) and node.asname == receiver:
            return True
    return False


_ASYNC_DRIVERS = {
    "run", "create_task", "ensure_future", "run_until_complete",
    "run_coroutine_threadsafe", "gather", "wait", "wait_for", "as_completed",
}


def _async_call_is_executed(call, parents) -> bool:
    """A call to an async function runs its coroutine when it is awaited, or when it is
    handed to an asyncio primitive that schedules/runs it (asyncio.run, create_task,
    ensure_future, gather, ..., or loop.run_until_complete). Such a call is live, not
    dead code, so its taint flow is reachable and must not be dropped as unawaited."""
    if _ancestor(call, parents, ast.Await) is not None:
        return True
    parent = parents.get(call)
    if isinstance(parent, ast.Call) and call is not parent.func:
        func = parent.func
        driver = (
            func.attr if isinstance(func, ast.Attribute)
            else func.id if isinstance(func, ast.Name)
            else ""
        )
        return driver in _ASYNC_DRIVERS
    return False


def _unawaited_async_flow(
    tree: ast.Module, source_line: int | None, sink_line: int,
    source_col: int | None = None, sink_col: int | None = None,
):
    parents = _parents(tree)
    async_functions = [
        node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef)
    ]
    for function in async_functions:
        source_inside = source_line is not None and (
            function.lineno <= source_line <= (function.end_lineno or function.lineno)
        )
        sink_inside = function.lineno <= sink_line <= (function.end_lineno or function.lineno)
        touches = sink_inside or source_inside
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == function.name
        ]
        relevant = [
            call for call in calls
            if (source_line is not None
                and _contains_position(call, source_line, source_col))
            or _contains_position(call, sink_line, sink_col)
        ]
        if touches and not relevant:
            relevant = calls
        if relevant and all(
            not _async_call_is_executed(call, parents) for call in relevant
        ):
            return True
    return False


def _finally_overrides_flow(tree: ast.Module, sink_line: int):
    parents = _parents(tree)
    for function in (
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        if not any(
            isinstance(node, ast.Try)
            and any(isinstance(item, ast.Return) for item in node.finalbody)
            for node in _scope_nodes(function)
        ):
            continue
        if any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == function.name
            and call.lineno <= sink_line <= (call.end_lineno or call.lineno)
            and _definition_visible(function, call, parents)
            for call in ast.walk(tree)
        ):
            return True
    return False


def _binding_at(scopes, name: str, line: int, col: int | None):
    return next(
        (found for scope in reversed(scopes)
         if (found := _last_binding(scope, name, line, col)) is not None),
        None,
    )


def _has_sink_import(
    scopes, name: str, suffix: str, line: int, col: int | None,
) -> bool:
    binding = _binding_at(scopes, name, line, col)
    if binding:
        return (
            binding[0] == "sink"
            or binding[0] == "import"
            and binding[1] + suffix in _PY_CANONICAL_SINKS
        )
    for scope in reversed(scopes):
        body = getattr(scope, "body", ())
        if not isinstance(body, list):
            continue
        for node in body:
            if not isinstance(node, ast.ImportFrom) or not _before(node, line, col):
                continue
            if any(alias.name == "*" for alias in node.names) and (
                "%s.%s" % (node.module, name) in _PY_CANONICAL_SINKS
            ):
                return True
    return False


def _was_sink_imported(
    scopes, name: str, suffix: str, line: int, col: int | None,
) -> bool:
    for scope in scopes:
        body = getattr(scope, "body", ())
        if not isinstance(body, list):
            continue
        for node in body:
            if not isinstance(node, (ast.Import, ast.ImportFrom)) or not _before(
                node, line, col
            ):
                continue
            imported = _import_binding(node, name)
            if imported and imported[1] + suffix in _PY_CANONICAL_SINKS:
                return True
            if isinstance(node, ast.ImportFrom) and any(
                alias.name == "*" for alias in node.names
            ) and "%s.%s" % (node.module, name) in _PY_CANONICAL_SINKS:
                return True
    return False


def _target_path(target):
    if isinstance(target, ast.Attribute):
        return dotted(target)
    if isinstance(target, ast.Subscript):
        return dotted(target.value)
    return None


def _assigned_expression(scopes, name: str, line: int, col: int | None):
    for scope in reversed(scopes):
        body = getattr(scope, "body", ())
        if not isinstance(body, list):
            continue
        for statement in reversed(body):
            if not isinstance(statement, ast.stmt) or not _before(statement, line, col):
                continue
            if isinstance(statement, ast.Assign):
                targets, value = statement.targets, statement.value
            elif isinstance(statement, ast.AnnAssign):
                targets, value = [statement.target], statement.value
            else:
                continue
            if value is not None and any(_target_binds(target, name) for target in targets):
                return value, statement
    return None


def _callable_identity(scopes, raw: str, line: int, col: int | None, seen=()):
    if raw in seen or len(seen) >= 16:
        return None
    name, separator, tail = raw.partition(".")
    binding = _binding_at(scopes, name, line, col)
    if binding and binding[0] == "import":
        return binding[1] + separator + tail
    if binding and binding[0] == "sink":
        return binding[1] + separator + tail
    assigned = _assigned_expression(scopes, name, line, col)
    if assigned:
        value, statement = assigned
        value_path = dotted(value)
        if value_path == name:
            return _callable_identity(
                scopes, raw, statement.lineno, statement.col_offset + 1, (*seen, raw),
            )
        if value_path:
            base = _callable_identity(
                scopes, value_path, statement.lineno, statement.col_offset + 1, (*seen, raw),
            )
            return base + separator + tail if base else None
        return None
    if not binding and name in _PY_BUILTIN_SINKS | {"input", "raw_input", "print"}:
        return "builtins." + raw
    return None


def _qualified_rebound(
    scopes, raw: str, line: int, col: int | None, *, unknown_is_rebound=False,
) -> bool:
    for scope in scopes:
        body = getattr(scope, "body", ())
        if not isinstance(body, list):
            continue
        for statement in body:
            if not isinstance(statement, ast.stmt) or not _before(statement, line, col):
                continue
            value = None
            if isinstance(statement, ast.Assign):
                targets, value = statement.targets, statement.value
            elif isinstance(statement, ast.AnnAssign):
                targets, value = [statement.target], statement.value
            elif isinstance(statement, ast.AugAssign):
                targets = [statement.target]
            elif isinstance(statement, ast.Delete):
                targets = statement.targets
            else:
                continue
            if any(_target_path(target) == raw for target in targets):
                if value is None:
                    return True
                expected = _callable_identity(
                    scopes, raw, statement.lineno, statement.col_offset + 1,
                )
                actual_path = dotted(value)
                actual = (_callable_identity(
                    scopes, actual_path, statement.lineno, statement.col_offset + 1,
                ) if actual_path else None)
                if expected and actual == expected:
                    continue
                if actual or isinstance(
                    value, (ast.Lambda, ast.Constant, ast.Dict, ast.List, ast.Set, ast.Tuple),
                ):
                    return True
                # Unknown assignments are not proof that the source or sink disappeared.
                return unknown_is_rebound
    return False


def _sink_is_shadowed(tree: ast.Module, line: int, col: int | None) -> bool:
    scopes = _scope_chain(tree, line, col)
    scope = scopes[-1]
    for node in _scope_nodes(scope):
        if not isinstance(node, ast.Call) or not _contains_position(node, line, col):
            continue
        call = dotted(node.func)
        if not call:
            continue
        name, separator, tail = call.partition(".")
        suffix = separator + tail
        builtin = not separator and name in _PY_BUILTIN_SINKS
        binding = _binding_at(scopes, name, line, col)
        imported_sink = _has_sink_import(scopes, name, suffix, line, col)
        if not builtin and not imported_sink:
            if call in _PY_CANONICAL_SINKS or _was_sink_imported(
                scopes, name, suffix, line, col
            ):
                return True
            continue
        if builtin and binding and not (
            binding[0] == "delete"
            or binding[0] == "import" and binding[1] == "builtins." + name
        ):
            return True
        if not builtin and binding and not (
            binding[0] == "sink"
            or binding[0] == "import" and binding[1] + suffix in _PY_CANONICAL_SINKS
        ):
            return True
        canonical = ("builtins." + name if builtin else (
            binding[1] + suffix if binding and binding[0] == "import" else call
        ))
        if _qualified_rebound(scopes, call, line, col) or (
            canonical != call and _qualified_rebound(scopes, canonical, line, col)
        ):
            return True
    return False


def _network_capability_is_invalid(
    tree: ast.Module, line: int, col: int | None,
) -> bool:
    """Reject a network-looking call unless its root is still bound to a known import."""
    allowed = {
        "requests.delete", "requests.get", "requests.head", "requests.options",
        "requests.patch", "requests.post", "requests.put", "requests.request",
        "httpx.delete", "httpx.get", "httpx.head", "httpx.options", "httpx.patch",
        "httpx.post", "httpx.put", "httpx.request", "httpx.stream",
        "urllib.request.urlopen", "urllib.request.urlretrieve",
        "socket.create_connection",
    }
    scopes = _scope_chain(tree, line, col)

    def canonical(raw, at_line=line, at_col=col):
        name, separator, tail = raw.partition(".")
        binding = _binding_at(scopes, name, at_line, at_col)
        if not binding or binding[0] != "import":
            return None
        return binding[1] + (separator + tail if separator else "")

    def assigned_constructor(name):
        for scope in reversed(scopes):
            body = getattr(scope, "body", ())
            if not isinstance(body, list):
                continue
            for candidate in reversed(body):
                if (not isinstance(candidate, (ast.Assign, ast.AnnAssign))
                        or not _before(candidate, line, col)):
                    continue
                targets = (candidate.targets if isinstance(candidate, ast.Assign)
                           else [candidate.target])
                if not any(dotted(target) == name for target in targets):
                    continue
                if dotted(candidate.value) == name:
                    continue
                if not isinstance(candidate.value, ast.Call):
                    return None
                return (dotted(candidate.value.func), candidate.lineno,
                        candidate.col_offset + 1)
        if "." not in name:
            return None
        assignments = []
        for candidate in ast.walk(tree):
            if not isinstance(candidate, (ast.Assign, ast.AnnAssign)):
                continue
            targets = (candidate.targets if isinstance(candidate, ast.Assign)
                       else [candidate.target])
            if any(dotted(target) == name for target in targets):
                assignments.append(candidate)
        if len(assignments) != 1 or not isinstance(assignments[0].value, ast.Call):
            return None
        candidate = assignments[0]
        return dotted(candidate.value.func), candidate.lineno, candidate.col_offset + 1

    for node in ast.walk(scopes[-1]):
        if not isinstance(node, ast.Call) or not _contains_position(node, line, col):
            continue
        raw = dotted(node.func)
        resolved = canonical(raw) if raw else None
        if (resolved in allowed
                and not _qualified_rebound(scopes, raw, line, col, unknown_is_rebound=True)
                and not (resolved != raw and _qualified_rebound(
                    scopes, resolved, line, col, unknown_is_rebound=True))):
            return False
        if not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        constructor = dotted(owner.func) if isinstance(owner, ast.Call) else None
        constructor_line, constructor_col = line, col
        if constructor is None and dotted(owner):
            assigned = assigned_constructor(dotted(owner))
            if assigned is not None:
                constructor, constructor_line, constructor_col = assigned
        resolved_constructor = canonical(
            constructor, constructor_line, constructor_col,
        ) if constructor else None
        if resolved_constructor in {
            "httpx.AsyncClient", "httpx.Client", "requests.Session",
        } and (node.func.attr in {
            "delete", "get", "head", "options", "patch", "post", "put", "request",
        } or (node.func.attr == "stream"
              and resolved_constructor in {"httpx.AsyncClient", "httpx.Client"})
        ) and not _qualified_rebound(
            scopes, constructor, constructor_line, constructor_col,
            unknown_is_rebound=True,
        ) and not _qualified_rebound(
            scopes, raw, line, col, unknown_is_rebound=True,
        ) and not (
            resolved_constructor != constructor
            and _qualified_rebound(
                scopes, resolved_constructor, constructor_line, constructor_col,
                unknown_is_rebound=True,
            )
        ):
            return False
    return True


def _assigned_alias_is_invalid(extra: dict, tree: ast.Module, line: int, col: int | None):
    metavars = extra.get("metavars")
    match = metavars.get("$ALIAS") if isinstance(metavars, dict) else None
    name = match.get("abstract_content") if isinstance(match, dict) else None
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_]\w*", name):
        return False
    binding = _binding_at(_scope_chain(tree, line, col), name, line, col)
    return not binding or binding[0] != "sink"


def _source_span(extra: dict, target_name: str, target: SelectedCode):
    try:
        kind, payload = extra["dataflow_trace"]["taint_source"]
        location, _content = payload
        line = location["start"]["line"]
        col = location["start"].get("col")
        end_line = location["end"].get("line")
        end_col = location["end"].get("col")
        path = location["path"]
    except (KeyError, TypeError, ValueError):
        metavars = extra.get("metavars")
        source = metavars.get("$SOURCE") if isinstance(metavars, dict) else None
        start = source.get("start") if isinstance(source, dict) else None
        end = source.get("end") if isinstance(source, dict) else None
        line = start.get("line") if isinstance(start, dict) else None
        col = start.get("col") if isinstance(start, dict) else None
        end_line = end.get("line") if isinstance(end, dict) else None
        end_col = end.get("col") if isinstance(end, dict) else None
        return (
            (line, col if type(col) is int and col >= 1 else None,
             end_line if type(end_line) is int else None,
             end_col if type(end_col) is int and end_col >= 1 else None)
            if type(line) is int and 1 <= line <= target.text.count("\n") + 1
            else (None, None, None, None)
        )
    if (kind != "CliLoc" or type(line) is not int
            or not 1 <= line <= target.text.count("\n") + 1
            or not isinstance(path, str)
            or _target_name(path) not in {target_name, _target_name(target.rel)}):
        return None, None, None, None
    return (
        line,
        col if type(col) is int and col >= 1 else None,
        end_line if type(end_line) is int else None,
        end_col if type(end_col) is int and end_col >= 1 else None,
    )


def _source_line(extra: dict, target_name: str, target: SelectedCode):
    return _source_span(extra, target_name, target)[0]


def _canonical_at(tree: ast.Module, raw: str, line: int, col: int):
    name, separator, tail = raw.partition(".")
    binding = _binding_at(_scope_chain(tree, line, col), name, line, col)
    if binding and binding[0] == "import":
        return binding[1] + separator + tail
    if not binding and name in {"input", "raw_input", "bytes", "bytearray"}:
        return "builtins." + raw
    return None


def _source_identity_is_invalid(
    tree: ast.Module, line: int | None, col: int | None, vector: str,
    end_line: int | None = None, end_col: int | None = None,
):
    if line is None:
        return False
    if vector == "SXV-008":
        protected = {"input", "raw_input", "sys", "os"}
        allowed = (
            "builtins.input", "builtins.raw_input", "sys.argv", "sys.stdin",
            "os.environ", "os.getenv",
        )
    elif vector == "SXV-018":
        protected = {"requests", "httpx", "urllib", "urllib3", "urlopen"}
        allowed = ("requests.", "httpx.", "urllib.request.urlopen", "urllib3.PoolManager")
    else:
        protected = {"base64", "binascii", "bytes", "bytearray"}
        allowed = ("base64.", "binascii.", "builtins.bytes.", "builtins.bytearray.")
    candidates = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Call, ast.Attribute, ast.Subscript)):
            continue
        within_span = (
            type(col) is int and type(end_line) is int and type(end_col) is int
            and (node.lineno, node.col_offset) >= (line, col - 1)
            and (node.end_lineno or node.lineno, node.end_col_offset or 0)
            <= (end_line, end_col - 1)
        )
        if not (within_span or end_line is None and _contains_position(node, line, col)):
            continue
        value = node.func if isinstance(node, ast.Call) else (
            node.value if isinstance(node, ast.Subscript) else node
        )
        raw = dotted(value)
        if not raw:
            continue
        canonical = _canonical_at(tree, raw, line, node.col_offset + 1)
        if (raw.split(".", 1)[0] in protected
                or canonical and canonical.startswith(allowed)):
            scopes = _scope_chain(tree, line, col)
            candidates.append(bool(
                canonical and canonical.startswith(allowed)
                and not _qualified_rebound(scopes, raw, line, col)
                and not (canonical != raw
                         and _qualified_rebound(scopes, canonical, line, col))
            ))
    if not candidates:
        return False
    return not any(candidates)


def _branch_at(branches, line: int):
    return next((index for index, body in enumerate(branches) if any(
        statement.lineno <= line <= (statement.end_lineno or statement.lineno)
        for statement in body
    )), None)


def _mutually_exclusive_lines(tree: ast.Module, first: int, second: int) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            branches = (node.body, node.orelse)
        elif isinstance(node, ast.Match):
            branches = tuple(case.body for case in node.cases)
        else:
            continue
        left, right = _branch_at(branches, first), _branch_at(branches, second)
        if left is not None and right is not None and left != right:
            # Different arms can both run on different loop iterations. Without a CFG that
            # proves a single iteration, keep the engine's flow instead of hiding a real one.
            repeated = any(
                isinstance(parent, (ast.For, ast.AsyncFor, ast.While))
                and parent is not node
                and parent.lineno <= node.lineno
                and (node.end_lineno or node.lineno)
                <= (parent.end_lineno or parent.lineno)
                for parent in ast.walk(tree)
            )
            if not repeated:
                return True
    return False


def _command_import_hides_outer_source(
    extra: dict, target_name: str, target: SelectedCode, tree: ast.Module,
    line: int, col: int | None,
) -> bool:
    metavars = extra.get("metavars")
    command_match = metavars.get("$COMMAND") if isinstance(metavars, dict) else None
    command = command_match.get("abstract_content") if isinstance(command_match, dict) else None
    if not isinstance(command, str) or not re.fullmatch(r"[A-Za-z_]\w*", command):
        return False
    scope = _scope_chain(tree, line, col)[-1]
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    if any(isinstance(node, ast.Global) and command in node.names for node in _scope_nodes(scope)):
        return False
    source = _source_line(extra, target_name, target)
    if source is None or scope.lineno <= source <= (scope.end_lineno or scope.lineno):
        return False
    binding = _last_binding(scope, command, line, col)
    return bool(binding and binding[0] == "import")


def _python_definite_false_positive(
    extra: dict, target_name: str, target: SelectedCode, vector: str,
    line: int, col: int | None, trees: dict[str, ast.Module | None],
) -> bool:
    if vector not in _PY_TAINT_VECTORS or target.suffix != ".py":
        return False
    if target_name not in trees:
        try:
            trees[target_name] = parse_python(target.text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            trees[target_name] = None
    tree = trees[target_name]
    source, source_col, source_end, source_end_col = _source_span(
        extra, target_name, target
    )
    return bool(tree and (
        _sink_is_shadowed(tree, line, col)
        or _source_identity_is_invalid(
            tree, source, source_col, vector, source_end, source_end_col
        )
        or _assigned_alias_is_invalid(extra, tree, line, col)
        or _call_flow_is_impossible(tree, source, line, source_col)
        or _receiver_flow_is_impossible(tree, line)
        or _unawaited_async_flow(tree, source, line, source_col, col)
        or _finally_overrides_flow(tree, line)
        or _command_import_hides_outer_source(extra, target_name, target, tree, line, col)
        or (source is not None
            and _mutually_exclusive_lines(tree, source, line))
    ))


def _scrub(value: object, prefixes=()) -> str:
    text = str(value or "")
    for prefix in prefixes:
        text = text.replace(str(prefix), "<local>")
    return text


def _validated_capability(target, name, capability, line, column, parsed, trees):
    if target.suffix != ".py":
        return True
    if name not in trees:
        artifact = parsed.by_rel.get(target.rel) if target.origin == "file" else None
        if artifact is not None:
            trees[name] = artifact.py_tree
        else:
            try:
                trees[name] = parse_python(target.text)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                trees[name] = None
    tree = trees[name]
    if tree is None:
        return None
    return not (capability == "execution" and _sink_is_shadowed(tree, line, column)
                or capability == "network" and _network_capability_is_invalid(tree, line, column))


def findings_from_report(
    report: dict,
    targets: dict[str, SelectedCode],
    *,
    parsed=None,
    redactions=(),
    observations=None,
) -> list[Finding]:
    """Translate OpenGrep's stable JSON result shape into native findings."""
    findings = []
    python_trees: dict[str, ast.Module | None] = {}
    postfilter_counts: dict[str, int] = {}
    capability_postfilter_counts: dict[str, int] = {}
    observation_trees: dict[str, ast.Module | None] = {}
    observation_counts: dict[str, int] = {}
    fence_sources = {}  # Split each captured source once across findings and trace steps.
    known_vectors = vector_registry()
    manifests = _manifest_index(parsed) if parsed is not None else {}
    results = report.get("results", [])
    errors = report.get("errors", [])
    if not isinstance(results, list):
        return [_coverage(
            "opengrep-invalid-output",
            "OpenGrep returned JSON with an unexpected result shape.",
            severity="high",
        )]
    if not isinstance(errors, list):
        findings.append(_coverage(
            "opengrep-invalid-output",
            "OpenGrep returned JSON with an unexpected error shape.",
            severity="high",
        ))
        errors = []
    if any(not isinstance(result, dict) for result in results):
        findings.append(_coverage(
            "opengrep-invalid-output",
            "OpenGrep returned a malformed result entry.",
            severity="high",
        ))
    if any(not isinstance(error, dict) for error in errors):
        findings.append(_coverage(
            "opengrep-invalid-output",
            "OpenGrep returned a malformed error entry.",
            severity="high",
        ))
    for result in results:
        if not isinstance(result, dict):
            continue
        target_name = _target_name(result.get("path"))
        target = targets.get(target_name)
        if target is None:
            findings.append(_coverage(
                "opengrep-unmapped-target",
                "OpenGrep returned a result for an unknown temporary target.",
                severity="high",
            ))
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        vector = metadata.get("skill_xray_vector")
        rule = metadata.get("skill_xray_rule")
        severity = metadata.get("skill_xray_severity")
        capability = metadata.get("skill_xray_capability")
        if not isinstance(vector, str) or vector not in known_vectors or not isinstance(rule, str):
            findings.append(_coverage(
                "opengrep-unmapped-rule",
                "OpenGrep rule `%s` has no valid Skill Xray mapping."
                % _rule_id(result.get("check_id", "?")),
                path=target.rel,
                severity="high",
            ))
            continue
        if severity not in ("critical", "high", "medium", "low"):
            severity = _SEVERITY.get(str(extra.get("severity", "")).upper(), "medium")
        # An installer-shaped HTTPS fetch (`curl https://cli.vendor.com/install.sh | sh`) is an
        # unpinned remote install, not a dropper: keep the finding, report it at medium. The whole
        # matched line is required so a TLS-bypass flag cannot hide inside the pattern's `...`.
        installer = False
        if rule == "opengrep-shell-fetch-pipe-exec" and severity in ("critical", "high"):
            matched_lines = extra.get("lines")
            if (isinstance(matched_lines, str) and matched_lines.strip()
                    and installer_idiom(matched_lines)):
                severity, installer = "medium", True
        # A script reading the skill's own install directory is not snooping on another agent:
        # keep the finding, report it at medium.
        own_path = False
        if rule == "opengrep-agent-config-read" and severity == "high":
            matched_lines = extra.get("lines")
            governing = _governing_manifest(manifests, target.rel)
            if isinstance(matched_lines, str) and own_install_path(matched_lines, governing):
                severity, own_path = "medium", True
        mapped_location = _location(result, target)
        if mapped_location is None:
            findings.append(_coverage(
                "opengrep-invalid-output",
                "OpenGrep returned a result with an invalid source location.",
                path=target.rel,
                severity="high",
            ))
            continue
        line, location = mapped_location
        metavars = extra.get("metavars")
        malformed_metavars = metavars is not None and (
            not isinstance(metavars, dict)
            or any(
                not isinstance(name, str)
                or not isinstance(match, dict)
                or ("abstract_content" in match
                    and not isinstance(match["abstract_content"], str))
                for name, match in metavars.items()
            )
        )
        if malformed_metavars:
            findings.append(_coverage(
                "opengrep-invalid-output",
                "OpenGrep returned malformed metavariable evidence.",
                path=target.rel,
                severity="high",
            ))
            metavars = None
        manifest = None
        declared = []
        if capability is not None:
            if (not isinstance(capability, str)
                    or capability not in {"execution", "network"} or parsed is None):
                findings.append(_coverage(
                    "opengrep-unmapped-rule",
                    "OpenGrep capability observation has no valid correlation mapping.",
                    path=target.rel, severity="high",
                ))
                continue
            if observations is not None:
                # Optional context cannot consume finding-validation budgets or populate its cache.
                count = observation_counts.get(target_name, 0)
                observation_counts[target_name] = count + 1
                valid = None
                reason = "validation-budget"
                if count < _MAX_POSTFILTERS_PER_TARGET:
                    reason = "observation-unvalidated"
                    try:
                        valid = _validated_capability(
                            target, target_name, capability, line, location["start"].get("col"),
                            parsed, observation_trees,
                        ) if not malformed_metavars else None
                    except Exception:
                        reason = "validation-error"
                if valid is not False and count <= _MAX_POSTFILTERS_PER_TARGET:
                    observations.append({
                        "path": target.rel, "line": line,
                        "column": location["start"].get("col"),
                        "capability": capability, "state": "present" if valid else "unknown",
                        "analyzer": "opengrep", "rule": rule, "vector": vector,
                        "engine_rule": _rule_id(result.get("check_id")), "origin": target.origin,
                        **({"reason": reason} if not valid else {}),
                    })
            manifest = _governing_manifest(manifests, target.rel)
            if manifest is None:
                continue
            if any(code == "frontmatter_parse_error" for code, _detail in manifest.diagnostics):
                findings.append(Finding(
                    vector="", rule="analysis-incomplete", severity="high",
                    path=target.rel,
                    message=("observed %s capability could not be compared because the "
                             "governing frontmatter is invalid" % capability),
                    evidence={
                        "phase": "correlation",
                        "reason": "capability-declaration-unparsed",
                        "manifest": manifest.rel,
                        "observed_capability": capability,
                    },
                ))
                continue
            frontmatter = manifest.frontmatter or {}
            has_allowed = "allowed-tools" in frontmatter
            has_denied = "disallowed-tools" in frontmatter
            if not has_allowed and not has_denied:
                continue
            malformed_empty = any(
                value is None or isinstance(value, str) and not value.strip()
                for present, value in (
                    (has_allowed, frontmatter.get("allowed-tools")),
                    (has_denied, frontmatter.get("disallowed-tools")),
                ) if present
            )
            grants = manifest.grants or []
            if (malformed_empty
                    or ("grants_unparsed_shape", "allowed-tools") in manifest.diagnostics
                    or ("grants_unparsed_shape", "disallowed-tools") in manifest.diagnostics
                    or any(not grant.parsed for grant in grants)):
                findings.append(Finding(
                    vector="", rule="analysis-incomplete", severity="high",
                    path=target.rel,
                    message=("observed %s capability could not be compared with the malformed "
                             "governing declaration" % capability),
                    evidence={
                        "phase": "correlation",
                        "reason": "capability-declaration-unparsed",
                        "manifest": manifest.rel,
                        "observed_capability": capability,
                    },
                ))
                continue
            if not has_allowed and capability not in denied_capabilities(grants):
                continue
            if capability in declared_capabilities(grants):
                continue
            # Only spend the AST validation budget once the capability is actually understated.
            if target.suffix == ".py":
                cap_count = capability_postfilter_counts.get(target_name, 0)
                capability_postfilter_counts[target_name] = cap_count + 1
                if cap_count >= _MAX_POSTFILTERS_PER_TARGET:
                    # SXV-033 needs confirmed behavior; past the budget fail visible, do not assert.
                    findings.append(Finding(
                        vector="", rule="analysis-incomplete", severity="high",
                        path=target.rel,
                        message=("observed %s capability could not be validated within the "
                                 "per-file budget" % capability),
                        evidence={
                            "phase": "correlation",
                            "reason": "capability-validation-budget",
                            "observed_capability": capability,
                        },
                    ))
                    continue
                if not _validated_capability(
                    target, target_name, capability, line, location["start"].get("col"),
                    parsed, python_trees,
                ):
                    continue
            declared = sorted(grant.tool for grant in effective_grants(grants) if grant.tool)
        python_candidate = vector in _PY_TAINT_VECTORS and target.suffix == ".py"
        needs_postfilter = python_candidate and not malformed_metavars
        postfilter_skipped = False
        if needs_postfilter:
            count = postfilter_counts.get(target_name, 0)
            postfilter_counts[target_name] = count + 1
            postfilter_skipped = count >= _MAX_POSTFILTERS_PER_TARGET
            dynamic_explicit_shell = False
            # After the reject-only validation budget, retain engine findings.
            if not postfilter_skipped:
                if target_name not in python_trees:
                    try:
                        python_trees[target_name] = parse_python(target.text)
                    except (SyntaxError, ValueError, RecursionError, MemoryError):
                        python_trees[target_name] = None
                tree = python_trees[target_name]
                shell_status, explicit_shell = _subprocess_shell_status(
                    tree, line, location["start"].get("col"),
                ) if tree else (True, False)
                if shell_status is False:
                    continue
                dynamic_explicit_shell = shell_status is None and explicit_shell
                if shell_status is None and not explicit_shell:
                    findings.append(Finding(
                        vector="",
                        rule="analysis-incomplete",
                        severity="high",
                        path=target.rel,
                        line=line,
                        message=("A tainted subprocess flow uses unresolved keyword arguments; "
                                 "execution eligibility could not be proven."),
                        evidence={
                            "engine": "opengrep",
                            "reason": "dynamic-subprocess-kwargs",
                            "origin": target.origin,
                        },
                    ))
                    continue
                if _python_definite_false_positive(
                    extra, target_name, target, vector, line,
                    location["start"].get("col"), python_trees,
                ):
                    continue
        evidence = {
            "engine": "opengrep",
            "engine_rule": _rule_id(result.get("check_id")),
            "origin": target.origin,
            **location,
        }
        if installer:
            evidence["installer_idiom"] = "https-named-installer"
        if own_path:
            evidence["own_install_path"] = True
        if capability is not None:
            evidence.update({
                "understated_capability": capability,
                "manifest": manifest.rel,
                "declared_tools": declared or ["(none)"],
            })
        if postfilter_skipped:
            evidence["postfilter"] = "retained-after-validation-budget"
        if needs_postfilter and dynamic_explicit_shell:
            evidence["shell_validation"] = "dynamic-explicit-shell-retained"
        for source, destination in (
            (extra.get("fingerprint"), "fingerprint"),
            (metavars, "metavars"),
            (extra.get("dataflow_trace"), "dataflow_trace"),
        ):
            if source:
                evidence[destination] = _remap_engine_paths(source, targets)
        if target.origin == "fence":
            _map_fence_evidence(evidence, target, targets, parsed,
                                extra.get("dataflow_trace"), fence_sources)
        findings.append(Finding(
            vector=vector,
            rule=rule,
            severity=severity,
            path=target.rel,
            line=line,
            column=(None if evidence.get("location_mapping") == "unvalidated"
                    else evidence["start"].get("col")),
            message=(
                "governing manifest %s does not declare observed %s capability"
                % (manifest.rel, capability)
                if capability is not None else
                "The script reads its own install directory under an agent's configuration root."
                if own_path else
                str(extra.get("message") or "OpenGrep detected a tainted flow.")[:800]
            ),
            evidence=evidence,
        ))

    for error in errors:
        if not isinstance(error, dict):
            continue
        target = targets.get(_target_name(error.get("path")))
        findings.append(_coverage(
            "opengrep-analysis-error",
            "OpenGrep could not fully analyze selected code: %s"
            % _scrub(error.get("message") or error.get("type") or "unknown error",
                     redactions)[:500],
            path=target.rel if target else "",
            severity="high",
        ))
    return dedupe_findings(findings)


def _coverage_from_report(report: dict, targets: dict[str, SelectedCode]) -> list[Finding]:
    paths = report.get("paths")
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
        return [_coverage(
            "opengrep-invalid-output",
            "OpenGrep did not report which selected targets it scanned.",
            severity="high",
        )]
    scanned = {_target_name(path) for path in paths["scanned"]}
    missing = sorted(set(targets) - scanned)
    if not missing:
        return []
    first = targets[missing[0]]
    return [_coverage(
        "opengrep-analysis-incomplete",
        "OpenGrep skipped %d selected code target(s); the candidate result is incomplete."
        % len(missing),
        path=first.rel,
        severity="high",
    )]


def _engine_env(root: Path) -> dict[str, str]:
    keep = (
        "ALLUSERSPROFILE", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)",
        "COMMONPROGRAMW6432", "COMPUTERNAME", "COMSPEC", "DRIVERDATA", "LANG",
        "LC_ALL", "NUMBER_OF_PROCESSORS", "OS", "PATH", "PATHEXT",
        "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
        "PROGRAMW6432", "PUBLIC", "SYSTEMDRIVE", "SYSTEMROOT", "USERPROFILE", "WINDIR",
    )
    source = {key.upper(): value for key, value in os.environ.items()}
    env = {key: source[key] for key in keep if key in source}
    home = root / "engine-home"
    temporary = root / "engine-tmp"
    home.mkdir()
    temporary.mkdir()
    cache = home / "cache"
    cache.mkdir()
    config = home / "config"
    config.mkdir()
    (home / ".opengrep").mkdir()
    env.update({
        "HOME": str(home),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
        "SEMGREP_SETTINGS_FILE": str(config / "settings.yml"),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "TMPDIR": str(temporary),
    })
    if os.name == "nt":
        # The v1.29 launcher needs the inherited USERPROFILE to locate its embedded runtime;
        # explicit XDG/settings/log paths still keep user configuration out of the scan.
        roaming = home / "AppData" / "Roaming"
        local = home / "AppData" / "Local"
        roaming.mkdir(parents=True)
        local.mkdir(parents=True)
        env.update({
            "APPDATA": str(roaming),
            "LOCALAPPDATA": str(local),
        })
        env["SEMGREP_LOG_FILE"] = str(root / "engine.log")
        env["SEMGREP_VERSION_CACHE_PATH"] = str(root / "version-cache")
    return env


def check(
    parsed,
    *,
    executable: str | None = None,
    rules: str | Path | None = None,
    timeout: float = 45.0,
    runner=None,
    code_units=None,
    languages=("python",),
    observations=None,
) -> list[Finding]:
    """Run OpenGrep and translate its report into native findings."""
    selected = select_executable_code(parsed, code_units, languages=languages)
    if not selected:
        return []
    injected_runner = runner is not None
    runner = runner or subprocess.run
    try:
        binary = executable if injected_runner and executable else resolve_opengrep(executable)
    except OpenGrepRuntimeError as exc:
        return [_coverage(
            "opengrep-unverified",
            str(exc),
            severity="high",
        )]
    if not binary:
        return [_coverage(
            "opengrep-unavailable",
            "Executable code was selected, but the OpenGrep binary is unavailable.",
            severity="high",
        )]
    rule_path = Path(rules).resolve() if rules else _RULES
    if not rule_path.is_file():
        return [_coverage(
            "opengrep-rules-unavailable",
            "Executable code was selected, but the local OpenGrep rules are unavailable.",
            severity="high",
        )]

    with tempfile.TemporaryDirectory(prefix="skill-xray-opengrep-") as temporary:
        root = Path(temporary)
        source_root = root / "targets"
        source_root.mkdir()
        report_path = root / "opengrep-report.json"
        stderr_path = root / "opengrep-stderr.txt"
        targets = {}
        for index, item in enumerate(selected):
            name = "%04d%s" % (index, item.suffix)
            with (source_root / name).open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(item.text)
            targets[name] = item
        command = [
            str(binary), "scan", "--json", "--dataflow-traces",
            "--disable-version-check", "--disable-nosem", "--no-git-ignore",
            # ponytail: one worker bounds package memory; raise it only after runtime calibration.
            "--jobs=1", "--max-memory=512", "--max-target-bytes=%d" % _MAX_TARGET_BYTES,
            "--max-match-per-file=1000", "--timeout=5", "--timeout-threshold=1",
            "--output", str(report_path),
            "--config", str(rule_path), str(source_root),
        ]
        try:
            with stderr_path.open("w+", encoding="utf-8", errors="replace") as stderr_handle:
                completed = runner(
                    command,
                    cwd=str(root),
                    env=_engine_env(root),
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_handle,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    check=False,
                )
                stderr_handle.seek(0)
                captured_stderr = stderr_handle.read(8192)
        except subprocess.TimeoutExpired:
            return [_coverage(
                "opengrep-timeout",
                "OpenGrep exceeded the package analysis deadline.",
                severity="high",
            )]
        except OSError as exc:
            return [_coverage(
                "opengrep-execution-error",
                "OpenGrep could not start: %s" % type(exc).__name__,
                severity="high",
            )]
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or captured_stderr
                      or "no diagnostic output").strip()
            detail = detail.replace(str(root), "<temporary>")
            detail = detail.replace(str(rule_path), "<rules>")
            return [_coverage(
                "opengrep-execution-error",
                "OpenGrep exited with status %d: %s"
                % (completed.returncode, detail[:500]),
                severity="high",
            )]
        try:
            report_size = report_path.stat().st_size
        except OSError:
            return [_coverage(
                "opengrep-invalid-output",
                "OpenGrep completed without producing its JSON report.",
                severity="high",
            )]
        if report_size > _MAX_REPORT_BYTES:
            return [_coverage(
                "opengrep-output-limit",
                "OpenGrep's JSON report exceeded the %d-byte limit."
                % _MAX_REPORT_BYTES,
                severity="high",
            )]
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeError):
            return [_coverage(
                "opengrep-invalid-output",
                "OpenGrep completed without returning valid JSON.",
                severity="high",
            )]
        if not isinstance(report, dict):
            return [_coverage(
                "opengrep-invalid-output",
                "OpenGrep returned an unexpected JSON document.",
                severity="high",
            )]
        return cap_findings(
            findings_from_report(
                report, targets, parsed=parsed, redactions=(root, rule_path, source_root),
                observations=observations,
            ) + _coverage_from_report(report, targets)
        )
