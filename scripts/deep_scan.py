#!/usr/bin/env python3
"""deep_scan - the four deep-scan kinds in ONE script (never split them).

Dead code and dependency cycles must share ONE import graph; complexity and
silent zones must share ONE parse. Splitting them into parallel scripts
produces contradictory conclusions ("unreachable" and "inside a reachable
cycle") and drifting metric definitions. There is exactly one main() and
one --kinds; the four kinds share a single parse of the tree.

Kinds:
  deadcode     reachability from entries; unreachable -> P2, dynamic
               reference (name in a string literal) -> INFO. Test files
               are exempt (frameworks call them, nothing imports them).
  dependency   module-level import cycles via SCC; 2-node direct -> P1,
               >2 nodes -> P2, lazy-import-only -> P2 "mitigated".
               Anchor: lexicographically smallest node first along the
               edge direction, first node repeated. Path: the file that
               holds the closing (back) edge.
  complexity   lines / nesting / McCabe with dual-condition baseline
               calibration (absolute floor OR max(floor, P95), n<30 ->
               floor). --calibrate-only computes metrics without judging.
  silent       candidate signals only (the script never grades them):
               empty catch / except pass (explanatory comment -> INFO),
               fallback passthrough, Go err discard / bare recover.

Languages: Python via ast; TypeScript/JavaScript and Go via brace-pair
scanners (stdlib only). Function anchors use the innermost module name
(file stem for py/ts, package name for go) - directory ownership is the
path field's job, not the anchor's.

Usage:
    python deep_scan.py --root <src> --kinds deadcode,dependency,complexity,silent
                         [--calibrate-only] [--thresholds <json>]
                         [--work-dir D] [--profile P] [--run-id X] [--selftest]

Outputs (under <work-dir>/out, overwrite mode):
    findings_deep.csv | metrics_deep.json | thresholds_<run-id>.json
    _done_deep.txt

Exit codes: 0 complete / 2 input error (missing root, bad kinds).
Standard library only; importing this module has no side effects.
"""
import argparse
import ast
import difflib
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweeplib as S  # noqa: E402
import profile as P  # noqa: E402

KINDS = ("deadcode", "dependency", "complexity", "silent")
PY_EXTS = (".py",)
TS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
GO_EXTS = (".go",)
TS_RESOLVE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

PY_ENTRY_NAMES = {"main.py", "__main__.py", "app.py", "wsgi.py", "asgi.py",
                  "manage.py"}
TS_ENTRY_NAMES = {"index.ts", "index.js", "index.tsx", "main.ts", "main.js",
                  "server.ts", "server.js", "app.ts", "app.js"}

TEST_FILE_RE = re.compile(
    r"(^|/)(test_[^/]+\.py|[^/]+_test\.py|[^/]+\.test\.(ts|tsx|js|jsx)|"
    r"[^/]+_test\.go)$|(^|/)tests?/")


def _is_test_file(rel):
    return TEST_FILE_RE.search(rel) is not None


# ------------------------------------------------------------------- model --

class Func(object):
    """One function/method. anchor is the stable identity (no line numbers)."""

    def __init__(self, module, name, path, lang, start, end, cls=""):
        self.module = module          # display module name (stem / package)
        self.name = name
        self.path = path              # project-relative file path
        self.lang = lang
        self.start = start            # 1-based first line (def line)
        self.end = end                # 1-based last line (inclusive)
        self.cls = cls
        self.lines = 0
        self.nesting = 0
        self.mccabe = 1
        self.calls = []               # (target_module_key, target_func_name)
        self.raw_calls = []           # (base_or_None, name), resolved later
        self.silent = []              # (signal, info_dict) candidates

    @property
    def anchor(self):
        if self.cls:
            return "%s.%s.%s" % (self.module, self.cls, self.name)
        return "%s.%s" % (self.module, self.name)


class Module(object):
    def __init__(self, key, display, path, lang):
        self.key = key                # internal identity (rel path / pkg dir)
        self.display = display        # anchor-visible module name
        self.path = path
        self.lang = lang
        self.imports = []             # (target_key, lazy)
        self.import_names = {}        # local name -> (target_key, orig_name)
        self.funcs = []
        self.strings = []
        self.entry_calls = []         # module-level calls (entry wiring)
        self.entry_raw_calls = []
        self.is_entry = False
        self.is_test = False
        self.source = None            # raw file text (python only)


# --------------------------------------------------------------- python AST --

def _py_module_name(rel):
    base = os.path.basename(rel)
    if base == "__init__.py":
        return os.path.basename(os.path.dirname(rel)) or base
    return base[:-3]


def _py_resolve(file_dir, root, level, module):
    """Resolve a python import to a project-relative file path or None."""
    if level:
        base = file_dir
        for _ in range(level - 1):
            base = os.path.dirname(base)
        parts = module.split(".") if module else []
        cand = os.path.join(base, *parts) if parts else base
    else:
        parts = module.split(".") if module else []
        if not parts:
            return None
        cand = os.path.join(root, *parts)
    if os.path.isfile(cand + ".py"):
        return os.path.relpath(cand + ".py", root).replace("\\", "/")
    init = os.path.join(cand, "__init__.py")
    if os.path.isfile(init):
        return os.path.relpath(init, root).replace("\\", "/")
    return None


def _py_mccabe(node):
    """1 + decision points (standard McCabe over the AST)."""
    score = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp)):
            score += 1
        elif isinstance(child, (ast.For, ast.AsyncFor, ast.While)):
            score += 1
        elif isinstance(child, ast.ExceptHandler):
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            score += 1 + len(child.ifs)
        elif isinstance(child, ast.Assert):
            score += 1
    return score


def _py_nesting(node):
    """Deepest control-structure nesting inside the function (body = 0)."""
    best = [0]

    def walk(n, depth):
        for child in ast.iter_child_nodes(n):
            if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While,
                                  ast.Try, ast.With, ast.AsyncWith)):
                best[0] = max(best[0], depth + 1)
                walk(child, depth + 1)
            else:
                walk(child, depth)
    walk(node, 0)
    return best[0]


def parse_python(path, rel, text, root):
    mod = Module(rel, _py_module_name(rel), rel, "python")
    mod.is_test = _is_test_file(rel)
    mod.source = text
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError:
        return mod, False
    file_dir = os.path.dirname(path)
    lines = text.split("\n")

    def empty_except(handler):
        """(is_empty, has_comment) for an except handler."""
        body = [s for st in handler.body for s in ast.walk(st)]
        is_empty = bool(handler.body) and all(
            isinstance(st, ast.Pass) for st in handler.body)
        has_comment = False
        end = max((getattr(st, "end_lineno", st.lineno)
                   for st in handler.body), default=handler.lineno)
        for ln in range(handler.lineno, end + 1):
            if 0 < ln <= len(lines) and lines[ln - 1].strip().startswith("#"):
                has_comment = True
                break
        return is_empty, has_comment

    class FuncScan(ast.NodeVisitor):
        def __init__(self):
            self.fn_stack = []
            self.cls_stack = []

        def visit_ClassDef(self, node):
            self.cls_stack.append(node.name)
            self.generic_visit(node)
            self.cls_stack.pop()

        def visit_FunctionDef(self, node):
            fn = Func(mod.display, node.name, rel, "python",
                      node.lineno, getattr(node, "end_lineno", node.lineno),
                      cls=self.cls_stack[-1] if self.cls_stack else "")
            fn.lines = fn.end - fn.start + 1
            fn.nesting = _py_nesting(node)
            fn.mccabe = _py_mccabe(node)
            fn.ast_node = node
            mod.funcs.append(fn)
            self.fn_stack.append(fn)
            self.generic_visit(node)
            self.fn_stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def _record_import(self, node):
            lazy = bool(self.fn_stack)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = _py_resolve(file_dir, root, 0, alias.name)
                    if target:
                        mod.imports.append((target, lazy))
                        mod.import_names[
                            alias.asname or alias.name.split(".")[0]] = (
                            target, alias.name.split(".")[-1])
                return
            # from X import a, b: X may itself be the target, but each name
            # may also be a SUBMODULE (`from . import svc_b` -> svc_b.py,
            # not the package __init__). Prefer the submodule file.
            base = _py_resolve(file_dir, root, node.level, node.module or "")
            if not base:
                return
            base_dir = os.path.dirname(os.path.join(root, base))
            for alias in node.names:
                target = base
                sub = _py_resolve(base_dir, root, 1, alias.name)
                if sub and sub != base:
                    target = sub
                mod.imports.append((target, lazy))
                mod.import_names[alias.asname or alias.name] = (
                    target, alias.name)

        def visit_Import(self, node):
            self._record_import(node)

        def visit_ImportFrom(self, node):
            self._record_import(node)

        def _record_call(self, node):
            """Record (base_or_None, name); resolution is deferred until the
            whole module is parsed (callees may be defined further down)."""
            func = node.func
            if isinstance(func, ast.Name):
                raw = (None, func.id)
            elif (isinstance(func, ast.Attribute)
                  and isinstance(func.value, ast.Name)):
                raw = (func.value.id, func.attr)
            else:
                return
            if self.fn_stack:
                self.fn_stack[-1].raw_calls.append(raw)
            else:
                mod.entry_raw_calls.append(raw)

        def visit_Call(self, node):
            self._record_call(node)
            # fallback passthrough: X.get(key, non-None default)
            if (isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and len(node.args) >= 2
                    and not (isinstance(node.args[1], ast.Constant)
                             and node.args[1].value is None)
                    and self.fn_stack):
                self.fn_stack[-1].silent.append(
                    ("deep.silent.fallback", {
                        "severity": "P2", "category": "兜底放行",
                        "symptom": "缺 key 时原样返回默认值（疑似静默降级）",
                        "evidence": "调用形态 X.get(key, default)，默认值非 None",
                    }))
            self.generic_visit(node)

        def visit_ExceptHandler(self, node):
            is_empty, has_comment = empty_except(node)
            if is_empty and self.fn_stack:
                sev = "INFO" if has_comment else "P2"
                note = ("空 except 带解释性注释，疑似故意忽略"
                        if has_comment else "空 except 无注释，错误被静默吞掉")
                self.fn_stack[-1].silent.append(
                    ("deep.silent.empty_catch", {
                        "severity": sev, "category": "静默吞错",
                        "symptom": note,
                        "evidence": "except 体仅含 pass%s"
                                    % ("（含解释性注释）" if has_comment else ""),
                    }))
            self.generic_visit(node)

    FuncScan().visit(tree)
    _resolve_raw_calls(mod)
    has_main_guard = any(
        isinstance(n, ast.If) and "main" in ast.dump(n.test)
        for n in tree.body)
    mod.is_entry = (os.path.basename(rel) in PY_ENTRY_NAMES
                    or has_main_guard)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            mod.strings.append(node.value)
    return mod, True


# ------------------------------------------------------- TS / JS (braces) --

def _brace_match(text, open_idx):
    """Index just past the '}' matching the '{' at open_idx (-1 if none)."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        elif c in "\"'`":
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\\":
                    j += 1
                j += 1
            i = j
        i += 1
    return -1


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def _ts_brace_depths(text):
    """Return at(idx) -> brace depth at that char index (strings skipped)."""
    depths = []
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depths.append(depth)
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
            depths.append(depth)
        else:
            depths.append(depth)
            if c in "\"'`":
                j = i + 1
                while j < n and text[j] != c:
                    if text[j] == "\\":
                        j += 1
                    j += 1
                for _k in range(i + 1, min(j + 1, n)):
                    depths.append(depth)
                i = j
        i += 1

    def at(idx):
        return depths[idx] if 0 <= idx < len(depths) else 0
    return at


TS_FUNC_RES = [
    re.compile(r"^[ \t]*(?:export\s+)?(?:async\s+)?function\s+"
               r"([A-Za-z_$][\w$]*)\s*\(", re.M),
    re.compile(r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)"
               r"\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\b|\()", re.M),
]
TS_IMPORT_RE = re.compile(
    r"""import\s+(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\{([^}]*)\})?"""
    r"""\s*from\s*["']([^"']+)["']""")
TS_REQUIRE_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*"""
    r"""["']([^"']+)["']\s*\)""")
TS_BARE_IMPORT_RE = re.compile(r"""^[ \t]*import\s+["']([^"']+)["']""", re.M)
TS_CATCH_RE = re.compile(r"(?<![.\w])catch\s*(?:\([^)]*\))?\s*\{")
TS_CALL_RE = re.compile(r"(?:(?P<mod>[A-Za-z_$][\w$]*)\s*\.\s*)?"
                        r"(?P<name>[A-Za-z_$][\w$]*)\s*\(")


def _ts_resolve(file_dir, root, spec):
    if not spec.startswith("."):
        return None
    base = os.path.normpath(os.path.join(file_dir, spec))
    for ext in TS_RESOLVE_EXTS:
        cand = base + ext
        if os.path.isfile(cand):
            return os.path.relpath(cand, root).replace("\\", "/")
    for ext in TS_RESOLVE_EXTS:
        cand = os.path.join(base, "index" + ext)
        if os.path.isfile(cand):
            return os.path.relpath(cand, root).replace("\\", "/")
    return None


def _ts_nesting(body):
    """Deepest control nesting inside a function body (body level = 0)."""
    best = 0
    depth = 0
    for m in re.finditer(r"\{|\}|(?<![.\w])(?:if|for|while|switch)\s*\(",
                         body):
        tok = m.group(0)
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
        else:
            best = max(best, depth)
    return best


def _ts_mccabe(body):
    score = 1
    score += len(re.findall(r"(?<![.\w])(?:if|for|while|case)\s*\(", body))
    score += len(re.findall(r"(?<![.\w])catch\s*\(", body))
    score += len(re.findall(r"&&|\|\|", body))
    stripped = body.replace("??", "")
    score += len(re.findall(r"\?(?![.=])", stripped))
    return score


def _ts_empty_catches(body):
    """[(is_empty, has_comment)] for every catch block in a function body."""
    out = []
    for m in TS_CATCH_RE.finditer(body):
        brace = m.end() - 1
        end_idx = _brace_match(body, brace)
        if end_idx < 0:
            continue
        inner = body[brace + 1:end_idx - 1]   # exclude both braces
        code = re.sub(r"//[^\n]*", " ", inner)
        code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
        is_empty = code.strip() == ""
        has_comment = ("//" in inner) or ("/*" in inner)
        out.append((is_empty, has_comment))
    return out


def parse_ts(path, rel, text, root):
    mod = Module(rel, os.path.basename(rel).rsplit(".", 1)[0], rel, "ts")
    mod.is_test = _is_test_file(rel)
    file_dir = os.path.dirname(path)
    depth_at = _ts_brace_depths(text)

    for m in TS_IMPORT_RE.finditer(text):
        target = _ts_resolve(file_dir, root, m.group(3))
        if not target:
            continue
        mod.imports.append((target, depth_at(m.start()) > 0))
        if m.group(2):
            for piece in m.group(2).split(","):
                piece = piece.strip()
                if not piece:
                    continue
                if piece.startswith("type "):
                    piece = piece[5:].strip()
                if " as " in piece:
                    local, orig = piece.split(" as ", 1)
                    mod.import_names[local.strip()] = (target, orig.strip())
                else:
                    mod.import_names[piece] = (target, piece)
        if m.group(1):
            mod.import_names[m.group(1)] = (target, "default")
    for m in TS_REQUIRE_RE.finditer(text):
        target = _ts_resolve(file_dir, root, m.group(2))
        if target:
            mod.imports.append((target, depth_at(m.start()) > 0))
            mod.import_names[m.group(1)] = (target, "default")
    for m in TS_BARE_IMPORT_RE.finditer(text):
        target = _ts_resolve(file_dir, root, m.group(1))
        if target:
            mod.imports.append((target, depth_at(m.start()) > 0))

    mod.is_entry = os.path.basename(rel) in TS_ENTRY_NAMES

    seen = set()
    for rx in TS_FUNC_RES:
        for m in rx.finditer(text):
            name = m.group(1)
            if (name, m.start()) in seen:
                continue
            seen.add((name, m.start()))
            brace = text.find("{", m.end() - 1)
            if brace < 0:
                continue
            end_idx = _brace_match(text, brace)
            if end_idx < 0:
                continue
            body = text[brace:end_idx]
            fn = Func(mod.display, name, rel, "ts", _line_of(text, m.start()),
                      _line_of(text, end_idx))
            fn.lines = fn.end - fn.start + 1
            fn.nesting = _ts_nesting(body)
            fn.mccabe = _ts_mccabe(body)
            mod.funcs.append(fn)
            # calls inside this body (resolved after the module is complete)
            for cm in TS_CALL_RE.finditer(body):
                fn.raw_calls.append((cm.group("mod"), cm.group("name")))
            # empty catch candidates
            for is_empty, has_comment in _ts_empty_catches(body):
                if is_empty:
                    sev = "INFO" if has_comment else "P2"
                    note = ("空 catch 带解释性注释，疑似故意忽略"
                            if has_comment else "空 catch 无注释，错误被静默吞掉")
                    fn.silent.append(("deep.silent.empty_catch", {
                        "severity": sev, "category": "静默吞错",
                        "symptom": note,
                        "evidence": "catch 体为空%s"
                                    % ("（含解释性注释）" if has_comment else ""),
                    }))
    # module-level calls (entry wiring)
    module_scope = _ts_module_scope(text)
    for cm in TS_CALL_RE.finditer(module_scope):
        mod.entry_raw_calls.append((cm.group("mod"), cm.group("name")))
    _resolve_raw_calls(mod)
    for m in re.finditer(r"""(?:"([^"\\]*)"|'([^'\\]*)'|`([^`\\]*)`)""",
                         text):
        mod.strings.append(m.group(0)[1:-1])
    return mod, True


def _ts_module_scope(text):
    """File text with every brace-matched function body blanked out."""
    spans = []
    for rx in TS_FUNC_RES:
        for m in rx.finditer(text):
            brace = text.find("{", m.end() - 1)
            if brace < 0:
                continue
            end_idx = _brace_match(text, brace)
            if end_idx > 0:
                spans.append((m.start(), end_idx))
    if not spans:
        return text
    spans.sort()
    out = []
    pos = 0
    for start, end in spans:
        if start < pos:
            continue
        out.append(text[pos:start])
        pos = end
    out.append(text[pos:])
    return "\n".join(out)


def _go_module_scope(text):
    """Go file text with every func body blanked out (module scope only)."""
    spans = []
    for m in GO_FUNC_RE.finditer(text):
        brace = text.find("{", m.end() - 1)
        if brace < 0:
            continue
        end_idx = _brace_match(text, brace)
        if end_idx > 0:
            spans.append((m.start(), end_idx))
    if not spans:
        return text
    spans.sort()
    out = []
    pos = 0
    for start, end in spans:
        if start < pos:
            continue
        out.append(text[pos:start])
        pos = end
    out.append(text[pos:])
    return "\n".join(out)


# ------------------------------------------------------------- Go (braces) --

GO_MOD_RE = re.compile(r"^\s*module\s+(\S+)", re.M)
GO_PKG_RE = re.compile(r"^\s*package\s+([A-Za-z_]\w*)", re.M)
GO_IMPORT_SINGLE_RE = re.compile(r"""^[ \t]*import\s+["']([^"']+)["']""",
                                 re.M)
GO_IMPORT_BLOCK_RE = re.compile(r"""import\s*\(([^)]*)\)""", re.S)
GO_FUNC_RE = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(",
                        re.M)
GO_ERR_DISCARD_RE = re.compile(
    r"(?:_|[A-Za-z_]\w*)\s*,\s*_\s*:?=\s*[A-Za-z_]\w*\s*\(")
GO_IF_ERR_RE = re.compile(r"if\s+err\s*!=\s*nil\s*\{")
GO_RECOVER_RE = re.compile(r"(?<![.\w])recover\s*\(\s*\)")
GO_LOG_RE = re.compile(
    r"(?<![.\w])(?:log|fmt)\.\w*(?:[Pp]rintf|rintln|Print|[Pp]rint)")


def _pkg_name_of(dir_path):
    if not os.path.isdir(dir_path):
        return None
    for name in sorted(os.listdir(dir_path)):
        if name.endswith(".go"):
            m = GO_PKG_RE.search(S.read_text(os.path.join(dir_path, name)))
            if m:
                return m.group(1)
    return None


def _go_nesting(body):
    best = 0
    depth = 0
    for m in re.finditer(r"\{|\}|(?<![.\w])(?:if|for|switch)\s*[^{]", body):
        tok = m.group(0)
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth -= 1
        else:
            best = max(best, depth)
    return best


def _go_mccabe(body):
    score = 1
    score += len(re.findall(r"(?<![.\w])(?:if|for|case)\s*[^{]", body))
    score += len(re.findall(r"&&|\|\|", body))
    return score


def parse_go(path, rel, text, root, go_mod):
    mod = Module(rel, "", rel, "go")
    mod.is_test = _is_test_file(rel)
    pkg_m = GO_PKG_RE.search(text)
    mod.display = pkg_m.group(1) if pkg_m else os.path.basename(
        os.path.dirname(path))
    mod.key = os.path.dirname(rel).replace("\\", "/") or "."
    mod.is_entry = (mod.display == "main")
    specs = []
    for m in GO_IMPORT_SINGLE_RE.finditer(text):
        specs.append(m.group(1))
    for m in GO_IMPORT_BLOCK_RE.finditer(text):
        for line in m.group(1).split("\n"):
            im = re.search(r"""["']([^"']+)["']""", line)
            if im:
                specs.append(im.group(1))
    prefix = (go_mod + "/") if go_mod else None
    for spec in specs:
        if prefix and spec.startswith(prefix):
            internal = spec[len(prefix):]
            abs_target = os.path.join(root, *internal.split("/"))
            # module keys are project-relative; keep the graph consistent
            tkey = os.path.relpath(abs_target, root).replace("\\", "/")
            mod.imports.append((tkey, False))
            pkg = _pkg_name_of(abs_target)
            if pkg:
                mod.import_names[pkg] = (tkey, "")
    for m in GO_FUNC_RE.finditer(text):
        brace = text.find("{", m.end() - 1)
        if brace < 0:
            continue
        end_idx = _brace_match(text, brace)
        if end_idx < 0:
            continue
        body = text[brace:end_idx]
        fn = Func(mod.display, m.group(1), rel, "go", _line_of(text, m.start()),
                  _line_of(text, end_idx))
        fn.lines = fn.end - fn.start + 1
        fn.nesting = _go_nesting(body)
        fn.mccabe = _go_mccabe(body)
        mod.funcs.append(fn)
        for cm in TS_CALL_RE.finditer(body):
            fn.raw_calls.append((cm.group("mod"), cm.group("name")))
        # silent: explicit err discard / bare recover
        if GO_ERR_DISCARD_RE.search(body) or GO_RECOVER_RE.search(body):
            fn.silent.append(("deep.silent.err_discard", {
                "severity": "P2", "category": "错误丢弃",
                "symptom": "error 被显式丢弃或裸 recover，无日志",
                "evidence": "形如 `_, _ = f()` / `x, _ := f()` / 裸 recover()",
            }))
        # silent: if err != nil { return ... } with no log call in the block
        for em in GO_IF_ERR_RE.finditer(body):
            brace2 = body.find("{", em.end() - 1)
            if brace2 < 0:
                continue
            end2 = _brace_match(body, brace2)
            if end2 < 0:
                continue
            block = body[brace2:end2]
            if re.search(r"(?<![.\w])return\b", block) and not \
                    GO_LOG_RE.search(block):
                fn.silent.append(("deep.silent.err_discard", {
                    "severity": "P2", "category": "错误丢弃",
                    "symptom": "if err != nil 块仅返回无日志（降级无痕）",
                    "evidence": "块内含 return 且无 log/fmt 输出调用",
                }))
    for m in re.finditer(r'"([^"\\]*)"', text):
        mod.strings.append(m.group(1))
    # module-level calls (main wiring)
    for cm in TS_CALL_RE.finditer(_go_module_scope(text)):
        mod.entry_raw_calls.append((cm.group("mod"), cm.group("name")))
    _resolve_raw_calls(mod)
    return mod, True


# ------------------------------------------------------------------ loading --

def load_modules(root):
    """One pass over the tree: parse every source file (shared by 4 kinds)."""
    modules = []
    unparsed = []
    go_mod = ""
    gomod_path = os.path.join(root, "go.mod")
    if os.path.isfile(gomod_path):
        m = GO_MOD_RE.search(S.read_text(gomod_path))
        go_mod = m.group(1) if m else ""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        dirnames[:] = [d for d in dirnames
                       if d not in P.SKIP_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace("\\", "/")
            if name.endswith(PY_EXTS):
                mod, ok = parse_python(path, rel, S.read_text(path), root)
            elif name.endswith(TS_EXTS):
                mod, ok = parse_ts(path, rel, S.read_text(path), root)
            elif name.endswith(GO_EXTS):
                mod, ok = parse_go(path, rel, S.read_text(path), root, go_mod)
            else:
                continue
            if not ok:
                unparsed.append(rel)
                continue
            modules.append(mod)
    return modules, unparsed


def build_call_graph(modules):
    """Resolve (module_key, name) call records into function-level edges."""
    by_key = {}
    for m in modules:
        by_key[m.key] = m
    edges = {}          # (caller path, anchor) -> set of (path, anchor)

    def targets_of(tkey, orig):
        tm = by_key.get(tkey)
        if tm is None:
            return []
        if orig:
            return [g for g in tm.funcs if g.name == orig]
        return list(tm.funcs)

    for m in modules:
        for f in m.funcs:
            for tkey, orig in f.calls:
                for g in targets_of(tkey, orig):
                    edges.setdefault((f.path, f.anchor), set()).add(
                        (g.path, g.anchor))
        for tkey, orig in m.entry_calls:
            for g in targets_of(tkey, orig):
                edges.setdefault(("<entry>", m.key), set()).add(
                    (g.path, g.anchor))
    return edges


def _resolve_raw_calls(mod):
    """Resolve (base, name) raw calls once the module is fully parsed.

    Deferred because a callee may be defined further down the file (or in
    another module not yet loaded); resolving during the scan pass silently
    drops forward references and produces fake dead code.
    """
    local_names = set(f.name for f in mod.funcs)

    def resolve(raw):
        base, name = raw
        if base is not None:
            if base in mod.import_names:
                return (mod.import_names[base][0], name)
            return None
        if name in mod.import_names:
            tkey, orig = mod.import_names[name]
            return (tkey, orig)
        if name in local_names:
            return (mod.key, name)
        return None

    for f in mod.funcs:
        for raw in f.raw_calls:
            r = resolve(raw)
            if r:
                f.calls.append(r)
    for raw in mod.entry_raw_calls:
        r = resolve(raw)
        if r:
            mod.entry_calls.append(r)


# --------------------------------------------------------------- analysis --

def module_graph(modules):
    """Adjacency of module-level import edges + lazy edges + all edges."""
    adj, lazy_adj, all_adj = {}, {}, {}
    for mod in modules:
        adj.setdefault(mod.key, set())
        lazy_adj.setdefault(mod.key, set())
        all_adj.setdefault(mod.key, set())
    for mod in modules:
        for target, lazy in mod.imports:
            if target not in all_adj:
                continue
            all_adj[mod.key].add(target)
            (lazy_adj if lazy else adj)[mod.key].add(target)
    return adj, lazy_adj, all_adj


def find_cycles(modules, adj, lazy_adj):
    """SCCs with >=2 nodes -> simple cycles (smallest display node first)."""
    index, low, on_stack, stack = {}, {}, set(), []
    counter = [0]
    sccs = []
    sys.setrecursionlimit(max(2000, len(adj) * 4))

    def strongconnect(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in sorted(adj.get(v, ())):
            if w not in index:
                strongconnect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1:
                sccs.append(comp)

    for v in sorted(adj):
        if v not in index:
            strongconnect(v)

    display = {m.key: m.display for m in modules}
    out = []
    for comp in sccs:
        members = set(comp)
        start = min(comp, key=lambda k: display.get(k, k))
        path = [start]
        seen = {start}

        def dfs(v):
            for w in sorted(adj.get(v, ()), key=lambda k: display.get(k, k)):
                if w not in members:
                    continue
                if w == start and len(path) >= 2:
                    return True
                if w in seen:
                    continue
                seen.add(w)
                path.append(w)
                if dfs(w):
                    return True
                path.pop()
            return False

        if not dfs(start):
            continue
        nodes = [display.get(k, k) for k in path]
        anchor = "->".join(nodes + [nodes[0]])
        close_file = ""
        for mod in modules:
            if mod.key == path[-1]:
                close_file = mod.path
                break
        edges = [(path[i], path[i + 1]) for i in range(len(path) - 1)]
        edges.append((path[-1], start))
        all_lazy = all(e in lazy_adj.get(e[0], set()) for e in edges)
        severity = "P1" if (len(path) == 2 and not all_lazy) else "P2"
        out.append({"anchor": anchor, "path": close_file,
                    "nodes": len(path), "severity": severity,
                    "all_lazy": all_lazy})
    out.sort(key=lambda c: (c["path"], c["anchor"]))
    return out


def find_deadcode(modules, all_adj, edges):
    """Reachability from entries. Test files are exempt (team-lead ruling)."""
    # module reachability: entries + everything transitively imported
    reachable_mods = set()
    frontier = [m.key for m in modules if m.is_entry and not m.is_test]
    while frontier:
        cur = frontier.pop()
        if cur in reachable_mods:
            continue
        reachable_mods.add(cur)
        for nxt in all_adj.get(cur, ()):
            if nxt not in reachable_mods:
                frontier.append(nxt)
    # conservative: a module imported by anyone is not an orphan module
    for m in modules:
        for target, _lazy in m.imports:
            reachable_mods.add(target)
    # a package __init__ is implicitly imported whenever the package is
    for m in modules:
        if os.path.basename(m.path) == "__init__.py":
            reachable_mods.add(m.key)

    # function reachability: roots are entry modules' functions, module-level
    # entry wiring calls, and (for go) package main functions
    roots = set()
    for m in modules:
        if m.is_test or m.key not in reachable_mods:
            continue
        if m.is_entry or m.display == "main":
            for f in m.funcs:
                roots.add((f.path, f.anchor))
    reachable = set()
    frontier = list(roots)
    while frontier:
        key = frontier.pop()
        if key in reachable:
            continue
        reachable.add(key)
        for nxt in edges.get(key, ()):
            if nxt not in reachable:
                frontier.append(nxt)

    all_strings = []
    for m in modules:
        all_strings.extend(m.strings)

    dead = []
    for m in modules:
        if m.is_test:
            continue
        if m.key not in reachable_mods:
            dead.append({"kind": "module", "module": m})
            continue
        for f in m.funcs:
            if (f.path, f.anchor) in reachable:
                continue
            dynamic = any(f.name in s for s in all_strings)
            dead.append({"kind": "fn", "module": m, "func": f,
                         "dynamic": dynamic})
    return dead


def find_dups(modules, min_lines, min_sim):
    """Cross-function duplicate blocks (normalized line sequences)."""
    def norm(line):
        s = line.strip()
        s = re.sub(r"#.*$", "", s)
        s = re.sub(r"//.*$", "", s)
        s = re.sub(r'"[^"]*"', '""', s)
        s = re.sub(r"'[^']*'", "''", s)
        s = re.sub(r"\b\d+(\.\d+)?\b", "#", s)
        return s.strip()

    seqs = []
    for m in modules:
        if m.is_test:
            continue
        for f in m.funcs:
            if f.lines < min_lines:
                continue
            seqs.append((f, f.norm_lines))
    out = []
    for i in range(len(seqs)):
        for j in range(i + 1, len(seqs)):
            fa, sa = seqs[i]
            fb, sb = seqs[j]
            if not sa or not sb:
                continue
            ratio = difflib.SequenceMatcher(None, sa, sb).ratio()
            if ratio >= min_sim and min(len(sa), len(sb)) >= min_lines:
                pair = sorted([fa.anchor, fb.anchor])
                out.append({"anchor": "%s|%s" % (pair[0], pair[1]),
                            "path": min(fa.path, fb.path),
                            "ratio": round(ratio, 3)})
    out.sort(key=lambda d: (d["path"], d["anchor"]))
    return out


def _norm_line(line):
    """Normalize a single source line for duplicate comparison."""
    s = line.strip()
    s = re.sub(r"#.*$", "", s)
    s = re.sub(r"//.*$", "", s)
    s = re.sub(r'"[^"]*"', '""', s)
    s = re.sub(r"'[^']*'", "''", s)
    s = re.sub(r"\b\d+(\.\d+)?\b", "#", s)
    return s.strip()


def find_dup_branch(func, source_lines, min_lines, min_sim):
    """Intra-function duplicate branch detection.

    Catches the real "冗余分支 / 逻辑写两遍" smell: an ``if/else`` (or
    ``if/elif/else``) whose two branches contain near-identical statement
    sequences. Unlike ``find_dups`` (cross-function), this is scoped to the
    branches of a single ``if`` so it stays precise and low false-positive.
    """
    node = getattr(func, "ast_node", None)
    if node is None or not source_lines:
        return []
    out = []

    def branch_seq(stmts):
        if not stmts:
            return []
        lo = min(s.lineno for s in stmts)
        hi = max(getattr(s, "end_lineno", s.lineno) for s in stmts)
        return [ln for ln in (_norm_line(source_lines[i - 1])
                              for i in range(lo, hi + 1)) if ln]

    for ifnode in ast.walk(node):
        if not isinstance(ifnode, ast.If):
            continue
        branches = [ifnode.body]
        if ifnode.orelse:
            # elif -> compare the elif body; else -> compare the else stmts
            if isinstance(ifnode.orelse[0], ast.If):
                branches.append(ifnode.orelse[0].body)
            else:
                branches.append(ifnode.orelse)
        seqs = [branch_seq(br) for br in branches]
        for i in range(len(seqs)):
            for j in range(i + 1, len(seqs)):
                a, b = seqs[i], seqs[j]
                if not a or not b:
                    continue
                if min(len(a), len(b)) < min_lines:
                    continue
                ratio = difflib.SequenceMatcher(None, a, b).ratio()
                if ratio >= min_sim:
                    out.append({"anchor": "%s:if@%d" % (func.anchor,
                                                         ifnode.lineno),
                                "path": func.path, "ratio": round(ratio, 3),
                                "line": ifnode.lineno})
    return out


# ------------------------------------------------------------- complexity --

def solve_thresholds(values, floors, overrides):
    """Dual condition: n<30 -> floor; P95<floor -> floor; else max(floor,P95)."""
    n = len(values.get("fn_lines") or [])
    solved = {}
    percentiles = {}
    for signal, floor in floors.items():
        vals = sorted(values.get(signal) or [])
        if not vals:
            solved[signal] = {"value": floor,
                              "source": "absolute-floor (no samples)"}
            continue

        def pct(q):
            k = (len(vals) - 1) * q
            lo = int(k)
            hi = min(lo + 1, len(vals) - 1)
            frac = k - lo
            return vals[lo] * (1 - frac) + vals[hi] * frac

        p95 = pct(0.95)
        percentiles[signal] = {
            "p50": round(pct(0.50), 2), "p90": round(pct(0.90), 2),
            "p95": round(p95, 2), "p99": round(pct(0.99), 2),
            "max": vals[-1],
        }
        if n < 30:
            value, source = floor, ("absolute-floor (n=%d < 30, percentile "
                                    "unreliable)" % n)
        elif p95 < floor:
            value, source = floor, ("absolute-floor (P95=%.1f < floor=%.1f, "
                                    "project uniformly low-quality)"
                                    % (p95, floor))
        else:
            value, source = max(floor, p95), "percentile-p95"
        if overrides.get(signal) is not None:
            value, source = overrides[signal], "user-override"
        solved[signal] = {"value": value, "source": source}
    return solved, percentiles, n


# --------------------------------------------------------------------- CLI --

def _selftest():
    ap = argparse.ArgumentParser(prog="deep_scan.py")
    ap.add_argument("--root", default=".")
    ap.add_argument("--kinds",
                    default="deadcode,dependency,complexity,silent")
    ap.add_argument("--work-dir", default=".")
    ap.add_argument("--profile", default="generic-polyglot")
    ap.parse_args(["--root", ".", "--kinds", "deadcode", "--work-dir", "."])
    print("OK deep_scan selftest: module imports cleanly, CLI parses, "
          "no network at import time")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    S.stdout_utf8()
    if "--selftest" in argv:
        return _selftest()
    ap = argparse.ArgumentParser(
        prog="deep_scan.py",
        description="bug-sweep 深度扫描（四类合一，一次解析共享产物）")
    ap.add_argument("--root", required=True, help="源码根目录（必填）")
    ap.add_argument("--kinds", required=True,
                    help="逗号分隔：deadcode,dependency,complexity,silent")
    ap.add_argument("--work-dir", required=True, help="工作目录（必填）")
    ap.add_argument("--profile", default="generic-polyglot", help="profile id")
    ap.add_argument("--calibrate-only", action="store_true",
                    help="只算指标与分位数，不判级")
    ap.add_argument("--thresholds", default=None,
                    help="用户阈值覆盖 JSON，如 {\"fn_lines\": 60}")
    ap.add_argument("--run-id", default="")
    args = ap.parse_args(argv)

    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()]
    unknown = [k for k in kinds if k not in KINDS]
    if unknown:
        sys.stderr.write("error: 未知 kind %s（可用：%s）\n"
                         % (",".join(unknown), ",".join(KINDS)))
        return 2
    if not kinds:
        sys.stderr.write("error: --kinds 不能为空\n")
        return 2
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        sys.stderr.write("error: 源码根目录不存在：%s\n" % root)
        return 2
    try:
        prof = P.load(args.profile, root)
    except P.ProfileError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2
    overrides = {}
    if args.thresholds:
        try:
            with open(args.thresholds, "r", encoding="utf-8") as f:
                overrides = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            sys.stderr.write("error: thresholds 文件不可读：%s\n" % e)
            return 2

    out_dir = os.path.join(args.work_dir, "out")
    os.makedirs(out_dir, exist_ok=True)
    w = S.LayerWriter(out_dir, "deep", "deep_scan.py", profile=prof)

    modules, unparsed = load_modules(root)
    complete = not unparsed
    edges = build_call_graph(modules)
    adj, lazy_adj, all_adj = module_graph(modules)
    funcs = [f for m in modules for f in m.funcs]

    # normalized line sequences for dup detection
    for m in modules:
        text = S.read_text(os.path.join(root, m.path))
        mlines = text.split("\n")
        for f in m.funcs:
            seg = mlines[f.start - 1:f.end]
            f.norm_lines = [ln.strip() for ln in seg
                            if ln.strip() and not ln.strip().startswith("#")]

    # deterministic run id from parsed content
    h = hashlib.sha1()
    for m in sorted(modules, key=lambda x: x.path):
        h.update(m.path.encode("utf-8"))
        h.update(str(len(m.funcs)).encode("utf-8"))
    run_id = args.run_id or h.hexdigest()[:12]

    # ---- complexity metrics + threshold calibration ----
    floors = {
        "fn_lines": int(prof.get("thresholds", {}).get("fn_lines", 40)),
        "max_nesting": int(prof.get("thresholds", {}).get("max_nesting", 3)),
        "mccabe": int(prof.get("thresholds", {}).get("mccabe", 10)),
    }
    values = {"fn_lines": [f.lines for f in funcs],
              "max_nesting": [f.nesting for f in funcs],
              "mccabe": [f.mccabe for f in funcs]}
    solved, percentiles, n_funcs = solve_thresholds(values, floors, overrides)
    thresholds_doc = {
        "run_id": run_id, "profile": prof.id, "n_functions": n_funcs,
        "mode": "calibrate" if args.calibrate_only else "judged",
        "percentiles": percentiles, "thresholds": solved,
    }
    th_path = os.path.join(out_dir, "thresholds_%s.json" % run_id)
    with open(th_path, "w", encoding="utf-8") as f:
        json.dump(thresholds_doc, f, ensure_ascii=False, indent=2,
                  sort_keys=True)

    w.set_metric("profile", prof.id)
    w.set_metric("run_id", run_id)
    w.set_metric("files", len(modules))
    w.set_metric("functions", len(funcs))
    w.set_metric("unparsed", unparsed)
    w.set_metric("thresholds", solved)
    w.set_metric("percentiles", percentiles)
    for m in modules:
        w.set_metric("func:%s" % m.path, len(m.funcs))

    if args.calibrate_only:
        w.flush()
        w.mark_done(len(modules), complete)
        print("deep_scan calibrate-only: %d files, %d functions, "
              "thresholds at %s" % (len(modules), len(funcs), th_path))
        return 0

    if "complexity" in kinds:
        sig_map = [("fn_lines", "deep.complexity.long_fn", "行数", "lines"),
                   ("max_nesting", "deep.complexity.deep_nesting", "嵌套",
                    "nesting"),
                   ("mccabe", "deep.complexity.high_mccabe", "圈复杂度",
                    "mccabe")]
        for metric, signal, label, attr in sig_map:
            th = solved[metric]["value"]
            src = solved[metric]["source"]
            for f in funcs:
                v = getattr(f, attr)
                if v > th:
                    w.add(signal, f.anchor, f.path, "P2", "复杂度超标",
                          "函数%s超阈值" % label,
                          "value=%s threshold=%s source=%s"
                          % (v, th, src), f.start)

    if "dependency" in kinds:
        for cyc in find_cycles(modules, adj, lazy_adj):
            if cyc["all_lazy"]:
                symptom = "模块循环依赖（仅延迟导入，有环但已规避）"
            elif cyc["nodes"] == 2:
                symptom = "模块循环依赖（2 节点直接环）"
            else:
                symptom = "模块循环依赖（间接环）"
            w.add("deep.dep.cycle", cyc["anchor"], cyc["path"],
                  cyc["severity"], "依赖环", symptom,
                  "环 %s（%d 节点；path 为闭合边所在文件）"
                  % (cyc["anchor"], cyc["nodes"]))

    if "deadcode" in kinds:
        for item in find_deadcode(modules, all_adj, edges):
            if item["kind"] == "module":
                mod = item["module"]
                w.add("deep.deadcode.module", mod.display, mod.path, "INFO",
                      "疑似死模块", "模块无人 import 且不在入口清单",
                      "入口注册常为动态，需人工确认")
            else:
                f = item["func"]
                if item["dynamic"]:
                    w.add("deep.deadcode.fn", f.anchor, f.path, "INFO",
                          "疑似死代码（动态引用）",
                          "函数不可达但名字出现在字符串字面量中",
                          "需人工确认是否为反射/字符串调用")
                else:
                    w.add("deep.deadcode.fn", f.anchor, f.path, "P2",
                          "疑似死代码", "从入口不可达且无动态引用证据",
                          "入口 + import 图全遍历后引用计数为 0", f.start)

    if "silent" in kinds:
        for m in modules:
            for f in m.funcs:
                for sig, info in f.silent:
                    w.add(sig, f.anchor, f.path, info["severity"],
                          info["category"], info["symptom"],
                          info["evidence"], f.start)

    if "complexity" in kinds:
        dup_min_lines = int(prof.get("thresholds", {}).get(
            "dup_min_lines", 12))
        dup_min_sim = float(prof.get("thresholds", {}).get(
            "dup_min_similarity", 0.85))
        dup_branch_min = int(prof.get("thresholds", {}).get(
            "dup_branch_min_lines", 4))
        for dup in find_dups(modules, dup_min_lines, dup_min_sim):
            w.add("deep.complexity.dup_block", dup["anchor"], dup["path"],
                  "P2", "重复代码", "跨函数重复代码块",
                  "相似度 %.3f（阈值行数 %d / 相似度 %.2f）"
                  % (dup["ratio"], dup_min_lines, dup_min_sim))
        for m in modules:
            if m.is_test or not m.source:
                continue
            src_lines = m.source.split("\n")
            for f in m.funcs:
                for dup in find_dup_branch(f, src_lines,
                                           dup_branch_min, dup_min_sim):
                    w.add("deep.complexity.dup_branch", dup["anchor"],
                          dup["path"], "P2", "冗余分支",
                          "if/else 两分支代码近乎相同（逻辑写两遍）",
                          "相似度 %.3f（阈值行数 %d / 相似度 %.2f）"
                          % (dup["ratio"], dup_branch_min, dup_min_sim),
                          dup["line"])

    w.flush()
    w.mark_done(len(modules), complete)

    print("deep_scan done: %d files, %d functions, %d findings, complete=%s"
          % (len(modules), len(funcs), len(w.findings),
             "true" if complete else "false"))
    if unparsed:
        print("  unparsed (complete=false): %s" % ", ".join(unparsed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
