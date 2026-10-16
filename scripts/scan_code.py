#!/usr/bin/env python3
"""scan_code - client layer scanner (pages, routes, dead code, hygiene).

Checks (all profile-driven, zero project facts in code):
  page.incomplete        page directory missing standard entry files (P2)
  route.dangling         manifest declares a page whose entry file is absent (P1)
  route.unregistered     page directory exists but is not in the manifest (INFO)
  route.manifest_broken  route manifest exists but is unparseable (P0, incomplete)
  deadcode.fn            exported function never referenced anywhere (P2)
  bak.file               backup file not covered by the ignore rules (P1/P2)
  client.placeholder_hit  whole-word placeholder residue in source (INFO)
  todo.marker            leftover TODO/FIXME/XXX marker (P2)
  share.matrix           paired share capabilities, asymmetric pages (INFO)

Preserved kernel mechanisms (must not be simplified):
  1. "Is an export referenced?" counts module-internal calls: a name seen once
     inside its own file is only the definition; >=2 occurrences in the own
     file, or >=1 in any other file, counts as used. Skipping this produces
     screens full of fake dead code.
  2. Backup files are checked against EVERY ignore-rule location from the
     profile before being reported: covered by all of them -> silent,
     covered by all but one -> P2, covered by none -> P1.
  3. Share capabilities are scanned as a PAIR and the full matrix is emitted;
     only asymmetric pages (one present, one absent) become INFO candidates.

Usage:
    python scan_code.py --root <client-dir> [--project-root <dir>]
                        [--work-dir D] [--profile P] [--run-id X] [--selftest]

Outputs (under <work-dir>/out, overwrite mode):
    findings_client.csv | metrics_client.json | _done_client.txt

Exit codes: 0 scan completed / 2 input error (missing root, unconfigured
profile, corrupt manifest handled as a P0 finding with complete=false).
Standard library only; importing this module has no side effects.
"""
import argparse
import fnmatch
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweeplib as S  # noqa: E402
import profile as P  # noqa: E402

# Source files considered for reference counting and text residue scans.
SOURCE_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".wxs")

# Export extraction from the API module (same shapes as the battle-tested
# original: function declarations and arrow/function const assignments).
EXPORT_FN_RE = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(",
    re.M)
EXPORT_CONST_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s*)?\(",
    re.M)
MODULE_EXPORTS_RE = re.compile(r"module\.exports\s*=\s*\{([^}]*)\}", re.S)

# Leftover development markers (documented client-layer criterion).
TODO_RE = re.compile(r"TODO|FIXME|XXX\b")

# Backup file / directory shapes (repository hygiene).
BAK_FILE_RE = re.compile(r"\.bak(\.\d+|$)|\.bak_|_bak_|~$")
BAK_DIR_NAMES = ("_bak", "backup")

TODO_MARKERS = ("TODO", "FIXME", "XXX")


# ------------------------------------------------------------------ helpers --

def _load_json(path):
    """Return (data, error). error is None on success."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except json.JSONDecodeError as e:
        return None, "JSON 解析失败（第 %d 行 %d 列）：%s" % (e.lineno, e.colno, e.msg)
    except OSError as e:
        return None, "无法读取：%s" % (e,)


def _iter_source_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in P.SKIP_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            if name.endswith(SOURCE_EXTS):
                yield os.path.join(dirpath, name)


def _iter_all_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in P.SKIP_DIRS and not d.startswith(".")]
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def _parse_ignore_patterns(text):
    """gitignore-ish line list: drop comments/blanks, keep the rest."""
    out = []
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def _pattern_covers(pattern, rel):
    """Does one gitignore-ish pattern cover the relative path?

    "name"      -> matches the basename or any path segment (dir or file)
    "a/b"       -> matched against the whole relative path
    "dir/"      -> matches any path segment equal to "dir"
    leading "!" (negation) is not supported and is ignored explicitly.
    """
    pat = pattern
    if pat.startswith("!"):
        return False
    if pat.endswith("/"):
        seg = pat[:-1]
        return any(s == seg for s in rel.split("/"))
    if "/" in pat:
        return fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*")
    base = rel.split("/")[-1]
    if fnmatch.fnmatch(base, pat):
        return True
    return any(fnmatch.fnmatch(s, pat) for s in rel.split("/")[:-1])


def _covered_count(patterns, rel):
    return sum(1 for p in patterns if _pattern_covers(p, rel))


# ------------------------------------------------------------------- scans --

def scan_pages(w, root, pages_dir, entry_files, rel):
    """page.incomplete: every page directory must carry the standard entries."""
    pages = []
    if os.path.isdir(pages_dir):
        pages = sorted(d for d in os.listdir(pages_dir)
                       if os.path.isdir(os.path.join(pages_dir, d)))
    missing_pages = []
    for page in pages:
        files = set(os.listdir(os.path.join(pages_dir, page)))
        missing = [f for f in entry_files if f not in files]
        if missing:
            missing_pages.append(page)
            w.add("page.incomplete", page, os.path.join(rel, page),
                  "P2", "页面文件不全",
                  "页面缺少标准入口文件",
                  "缺 %s；实际文件 %s" % (",".join(missing),
                                         ",".join(sorted(files))))
    return pages, missing_pages


def scan_routes(w, root, rel, manifest_rel, pages, entry_files):
    """route.dangling / route.unregistered / route.manifest_broken."""
    manifest_path = os.path.join(root, manifest_rel) if manifest_rel else ""
    declared = []
    broken = None
    if manifest_rel and os.path.exists(manifest_path):
        data, err = _load_json(manifest_path)
        if err:
            broken = err
            w.add("route.manifest_broken", manifest_rel, manifest_rel,
                  "P0", "配置损坏",
                  "路由声明文件无法解析，路由对齐检查未执行",
                  "%s（manifest=%s）" % (err, manifest_rel))
        else:
            declared = list(data.get("pages", []) or [])
            for sub in (data.get("subPackages", [])
                        or data.get("subpackages", []) or []):
                base = (sub.get("root", "") or "").strip("/")
                for pg in (sub.get("pages", []) or []):
                    declared.append((base + "/" + pg).strip("/") if base else pg)
    dangling = []
    for route in declared:
        route = str(route).strip("/")
        if not route:
            continue
        hit = False
        for ext_entry in entry_files:
            stem, dot, ext = ext_entry.partition(".")
            if dot and os.path.exists(os.path.join(root, route + "." + ext)):
                hit = True
                break
            if os.path.exists(os.path.join(root, route, ext_entry)):
                hit = True
                break
        if not hit:
            dangling.append(route)
            w.add("route.dangling", route, manifest_rel, "P1", "路由悬空",
                  "路由声明指向的页面入口不存在",
                  "未找到 %s 的任何入口文件（%s）"
                  % (route, "/".join(entry_files)))
    unregistered = []
    declared_norm = set(str(d).replace("\\", "/").strip("/") for d in declared)
    for page in pages:
        cands = {"pages/%s/index" % page, "pages/%s/%s" % (page, page)}
        if not (cands & declared_norm):
            unregistered.append(page)
            w.add("route.unregistered", page, "pages/%s" % page, "INFO",
                  "路由未注册", "页面目录未出现在路由声明中",
                  "pages/%s 不在 manifest 的 pages/subPackages 中" % page)
    return declared, dangling, unregistered, broken


def scan_deadcode(w, root, rel, api_module_rel):
    """deadcode.fn with the module-internal-call rule (mechanism 1)."""
    note = None
    unused = []
    exported_baseline = []
    api_path = os.path.join(root, api_module_rel) if api_module_rel else ""
    if not api_module_rel:
        note = "profile 未配置 roots.api_module，跳过导出死代码检查"
        return unused, note, exported_baseline
    if not os.path.exists(api_path):
        note = "api 模块不存在：%s，跳过导出死代码检查" % api_module_rel
        return unused, note, exported_baseline
    src = S.read_text(api_path)
    exports = EXPORT_FN_RE.findall(src) + EXPORT_CONST_RE.findall(src)
    seen = set()
    ordered = []
    for name in exports:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    me = MODULE_EXPORTS_RE.search(src)
    if me:
        exported_baseline = [x.strip().split(":")[0].strip()
                             for x in me.group(1).split(",") if x.strip()]
    bodies = []
    for full in _iter_source_files(root):
        try:
            text = S.read_text(full)
        except OSError:
            continue
        # The module.exports block is wiring, not a call: listing a function
        # there must not count as a reference, otherwise every export looks
        # "used" inside its own file and deadcode.fn can never fire.
        if os.path.abspath(full) == os.path.abspath(api_path):
            text = MODULE_EXPORTS_RE.sub("", text)
        bodies.append((os.path.abspath(full), text))
    api_abs = os.path.abspath(api_path)
    for name in ordered:
        rx = re.compile(r"\b%s\b" % re.escape(name))
        used = False
        for abs_path, text in bodies:
            n = len(rx.findall(text))
            if abs_path == api_abs:
                if n >= 2:      # definition + at least one internal call
                    used = True
                    break
            elif n >= 1:
                used = True
                break
        if not used:
            unused.append(name)
            w.add("deadcode.fn", "%s.%s" % (api_module_rel, name),
                  api_module_rel, "P2", "死代码",
                  "导出函数全工程无引用",
                  "%s 在 %s 及全部源码中出现次数不足以认定被使用"
                  % (name, api_module_rel))
    return unused, note, exported_baseline


def scan_hygiene(w, root, project_root, rel, ignore_specs):
    """bak.file: check every ignore-rule location first (mechanism 2)."""
    patterns_by_source = []
    for spec in ignore_specs or []:
        p = os.path.join(project_root, spec)
        pats = []
        if os.path.exists(p):
            if p.endswith(".json"):
                data, err = _load_json(p)
                if not err and isinstance(data, dict):
                    pack = data.get("packOptions", {}) or {}
                    pats = [str(x) for x in (pack.get("ignore", []) or [])]
            else:
                pats = _parse_ignore_patterns(S.read_text(p))
        patterns_by_source.append((spec, pats))
    total = len(patterns_by_source)
    uncovered = []
    partially = []
    for full in _iter_all_files(root):
        name = os.path.basename(full)
        rel_to_root = os.path.relpath(full, root).replace("\\", "/")
        if not BAK_FILE_RE.search(name):
            continue
        covered = _covered_count([p for _, pats in patterns_by_source
                                  for p in pats], rel_to_root)
        if covered == 0:
            uncovered.append(rel_to_root)
            w.add("bak.file", name, rel_to_root, "P1", "仓库卫生",
                  "备份文件未被任何忽略规则覆盖，可能打进发布包",
                  "%d 处忽略规则（%s）均未覆盖"
                  % (total, ", ".join(s for s, _ in patterns_by_source)))
        elif covered < total:
            partially.append(rel_to_root)
            w.add("bak.file", name, rel_to_root, "P2", "仓库卫生",
                  "备份文件仅被部分忽略规则覆盖",
                  "%d/%d 处忽略规则覆盖（%s）"
                  % (covered, total,
                     ", ".join(s for s, _ in patterns_by_source)))
    # Backup directories: same rule, reported per directory.
    for dirpath, dirnames, _files in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in P.SKIP_DIRS and not d.startswith(".")]
        for d in list(dirnames):
            if d in BAK_DIR_NAMES or d.startswith("_bak"):
                rel_dir = os.path.relpath(os.path.join(dirpath, d),
                                          root).replace("\\", "/")
                covered = _covered_count([p for _, pats in patterns_by_source
                                          for p in pats], rel_dir)
                if covered == 0:
                    w.add("bak.file", d, rel_dir, "P1", "仓库卫生",
                          "备份目录未被任何忽略规则覆盖",
                          "%d 处忽略规则均未覆盖" % total)
                elif covered < total:
                    w.add("bak.file", d, rel_dir, "P2", "仓库卫生",
                          "备份目录仅被部分忽略规则覆盖",
                          "%d/%d 处忽略规则覆盖" % (covered, total))
    return uncovered, partially


def scan_text(w, root, rel, words):
    """client.placeholder_hit (INFO) + todo.marker (P2), whole-word matching."""
    placeholder_hits = {}
    todo_hits = {}
    scanned = 0
    for full in _iter_source_files(root):
        scanned += 1
        relf = os.path.relpath(full, root).replace("\\", "/")
        text = S.read_text(full)
        for word, off in S.whole_word_hits(text, words):
            placeholder_hits.setdefault((word, relf), []).append(off)
        for m in TODO_RE.finditer(text):
            line_no = text[:m.start()].count("\n") + 1
            todo_hits.setdefault((m.group(0), relf), []).append(line_no)
    for (word, relf), offs in sorted(placeholder_hits.items()):
        w.add("client.placeholder_hit", word, relf, "INFO", "占位词残留",
              "源码含整词占位词（需人工确认是否用户可见）",
              "整词命中 %d 处（首处偏移 %d）" % (len(offs), offs[0]))
    for (marker, relf), lines in sorted(todo_hits.items()):
        w.add("todo.marker", marker, relf, "P2", "遗留标记",
              "源码含遗留开发标记",
              "命中 %d 处，行号 %s"
              % (len(lines), ",".join(str(x) for x in lines[:12])))
    return placeholder_hits, todo_hits, scanned


# ----------------------------------------------------------------- Python 反模式
# 来自真实修复记录(规则11校准集)的Python反模式：代理后误信客户端IP、配置默认
# 值为占位串、默认AI供应商为mock、硬编码默认凭据、未校验重定向、未转义HTML入库、
# os.getenv未配load_dotenv。全部为与profile无关的正则，仅当profile开启
# signals.python_antipatterns 时运行(避免污染通用扫描/selftest)。
PY_EXTS = (".py",)
PROXY_IP_RE = re.compile(r"request\.client\.host")
PLACEHOLDER_RE = re.compile(
    r"os\.getenv\([^,)]*,\s*[\"'](?:粤ICP备[^ \"']*|XXXXXXXX|placeholder|"
    r"待补充|待查证|待实测)[\"']")
MOCK_DEFAULT_RE = re.compile(r"os\.getenv\([^,)]*,\s*[\"']mock[\"']")
HARDCODED_CRED_RE = re.compile(
    r"hash_password\(\s*[\"']([^\"']+)[\"']\s*\)|password\s*=\s*[\"']([^\"']{1,32})[\"']")
REDIRECT_SAFE_RE = re.compile(r"is_safe_redirect_url|sanitize_redirect")
ESCAPE_HTML_RE = re.compile(r"sanitize_html|markupsafe|escape\(")
LOAD_DOTENV_RE = re.compile(r"load_dotenv\s*\(")


def scan_python_antipatterns(w, root, rel):
    """真实修复记录反模式(Python)。profile 开启 python_antipatterns 才运行。"""
    for full in _iter_all_files(root):
        if not full.endswith(PY_EXTS):
            continue
        relf = os.path.relpath(full, root).replace("\\", "/")
        try:
            text = S.read_text(full)
        except OSError:
            continue
        if PROXY_IP_RE.search(text):
            w.add("code.proxy_ip_trust", relf, relf, "P1", "代理后误信客户端IP",
                  "代理/负载均衡后使用 request.client.host 取客户端IP，"
                  "应读 X-Forwarded-For", "命中 request.client.host")
        if PLACEHOLDER_RE.search(text):
            w.add("code.default_placeholder", relf, relf, "P1", "配置默认值为占位串",
                  "os.getenv 默认值仍是占位串（如粤ICP备XXXXXXXX号）",
                  "命中占位默认值")
        if MOCK_DEFAULT_RE.search(text):
            w.add("code.default_mock_provider", relf, relf, "P1",
                  "默认AI供应商为mock",
                  "AI_PROVIDER 默认 mock，生产会静默走假模型",
                  '命中 os.getenv(..., "mock")')
        m = HARDCODED_CRED_RE.search(text)
        if m:
            w.add("secret.default_credential", relf, relf, "P1", "硬编码默认凭据",
                  "默认口令/哈希以字面量硬编码（应从环境变量读取）",
                  "命中 %s" % m.group(0)[:48])
        has_request = "request" in text
        if has_request and not REDIRECT_SAFE_RE.search(text) \
                and re.search(r"url\s*=|buy_link|redirect", text):
            w.add("code.unvalidated_redirect", relf, relf, "P1",
                  "未校验的重定向/外链",
                  "从 request 取 url/外链但未调用 is_safe_redirect_url 校验",
                  "命中未校验外链")
        if has_request and re.search(r"content|html", text) \
                and not ESCAPE_HTML_RE.search(text):
            w.add("code.unescaped_html_storage", relf, relf, "P2",
                  "未转义的HTML入库",
                  "从 request 取 content/html 但未调用 sanitize_html 转义",
                  "命中未转义入库")
        if "os.getenv" in text and not LOAD_DOTENV_RE.search(text):
            w.add("code.missing_load_dotenv", relf, relf, "P2",
                  "os.getenv 未配 load_dotenv",
                  "使用 os.getenv 读配置但未 load_dotenv()，.env 不进 "
                  "os.environ 会导致配置误读/误报",
                  "命中 os.getenv 无 load_dotenv")


def scan_share_matrix(w, root, pages_dir, pages, capabilities):
    """share.matrix: paired capabilities, full matrix in metrics (mechanism 3)."""
    matrix = {}
    asymmetric = []
    if not capabilities or len(capabilities) < 2 or not pages:
        return matrix, asymmetric
    names = [c.get("name", "") for c in capabilities]
    for page in pages:
        entry = None
        pdir = os.path.join(pages_dir, page)
        for f in sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []:
            if f.endswith((".js", ".ts")):
                entry = os.path.join(pdir, f)
                break
        row = []
        text = S.read_text(entry) if entry else ""
        for cap in names:
            row.append(bool(re.search(r"\b%s\b" % re.escape(cap), text))
                       if cap else False)
        matrix[page] = row
        if any(row) and not all(row):
            asymmetric.append(page)
            w.add("share.matrix", page, "pages/%s" % page, "INFO",
                  "分享能力不成对",
                  "成对分享能力只开了一半（可能故意豁免，需人工标注）",
                  "矩阵 %s" % " | ".join(
                      "%s=%s" % (c.get("label") or c.get("name") or "?",
                                 "有" if v else "无")
                      for c, v in zip(capabilities, row)))
    return matrix, asymmetric


# --------------------------------------------------------------------- CLI --

def _selftest():
    """Gate 1: importable, args parse, no network, no side effects."""
    ap = argparse.ArgumentParser(prog="scan_code.py")
    ap.add_argument("--root", default=".")
    ap.add_argument("--project-root", default=None)
    ap.add_argument("--work-dir", default=".")
    ap.add_argument("--profile", default="generic-polyglot")
    ap.add_argument("--run-id", default="")
    ap.add_argument("--selftest", action="store_true")
    ap.parse_args(["--root", ".", "--work-dir", ".", "--selftest"])
    print("OK scan_code selftest: module imports cleanly, CLI parses, "
          "no network at import time")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    S.stdout_utf8()
    if "--selftest" in argv:
        return _selftest()
    ap = argparse.ArgumentParser(
        prog="scan_code.py",
        description="bug-sweep 客户端层扫描（页面 / 路由 / 死代码 / 仓库卫生）")
    ap.add_argument("--root", required=True, help="客户端根目录（必填）")
    ap.add_argument("--project-root", default=None,
                    help="项目根目录（忽略规则以此解析，缺省同 --root）")
    ap.add_argument("--work-dir", required=True, help="工作目录（必填）")
    ap.add_argument("--profile", default="generic-polyglot", help="profile id")
    ap.add_argument("--run-id", default="", help="运行 ID（记录用）")
    ap.add_argument("--selftest", action="store_true", help="内置自检")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()

    root = os.path.abspath(args.root)
    project_root = os.path.abspath(args.project_root or args.root)
    if not os.path.isdir(root):
        sys.stderr.write("error: 客户端根目录不存在：%s\n" % args.root)
        return 2
    try:
        prof = P.load(args.profile, project_root)
    except P.ProfileError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2

    roots = prof.get("roots", {}) or {}
    pages_rel = roots.get("pages_dir", "pages")
    manifest_rel = roots.get("routes_manifest", "")
    api_module_rel = roots.get("api_module", "")
    ignore_specs = roots.get("ignore_rules", []) or []
    entry_files = prof.get("entry_files", []) or ["index.js"]
    words = (prof.get("signals", {}) or {}).get("placeholder_words", []) or []
    capabilities = (prof.get("signals", {}) or {}).get("share_capabilities", []) or []

    if not manifest_rel and not pages_rel:
        sys.stderr.write(
            "error: profile %s 未配置 roots.pages_dir / roots.routes_manifest，"
            "客户端层不可用。通用项目请用 --profile generic-polyglot "
            "配合 deep_scan.py 只跑内核判据。\n" % args.profile)
        return 2

    out_dir = os.path.join(args.work_dir, "out")
    os.makedirs(out_dir, exist_ok=True)
    rel = os.path.relpath(root, project_root).replace("\\", "/")
    if rel == ".":
        rel = ""
    w = S.LayerWriter(out_dir, "client", "scan_code", profile=prof)

    complete = True
    notes = []

    pages, missing_pages = scan_pages(
        w, root, os.path.join(root, pages_rel), entry_files, rel)
    declared, dangling, unregistered, broken = scan_routes(
        w, root, rel, manifest_rel, pages, entry_files)
    if broken:
        complete = False
    if manifest_rel and not pages:
        notes.append("routes manifest 存在但页面目录 %s 不存在，"
                     "页面清单检查未执行" % pages_rel)
        complete = False
    unused, deadcode_note, exported_baseline = scan_deadcode(
        w, root, rel, api_module_rel)
    if deadcode_note:
        notes.append(deadcode_note)
    uncovered, partially = scan_hygiene(
        w, root, project_root, rel, ignore_specs)
    placeholder_hits, todo_hits, scanned = scan_text(w, root, rel, words)
    if (prof.get("signals", {}) or {}).get("python_antipatterns", False):
        scan_python_antipatterns(w, root, rel)
    matrix, asymmetric = scan_share_matrix(
        w, root, os.path.join(root, pages_rel), pages, capabilities)

    w.set_metric("profile", prof.id)
    w.set_metric("client_root", rel or ".")
    w.set_metric("pages", len(pages))
    w.set_metric("pages_missing_entries", len(missing_pages))
    w.set_metric("declared_routes", len(declared))
    w.set_metric("dangling_routes", len(dangling))
    w.set_metric("unregistered_pages", len(unregistered))
    w.set_metric("unused_exports", len(unused))
    w.set_metric("export_baseline", exported_baseline)
    w.set_metric("bak_uncovered", len(uncovered))
    w.set_metric("bak_partially_covered", len(partially))
    w.set_metric("placeholder_hits", len(placeholder_hits))
    w.set_metric("todo_hits", len(todo_hits))
    w.set_metric("share_matrix", matrix)
    w.set_metric("share_asymmetric", asymmetric)
    w.set_metric("source_files_scanned", scanned)
    if args.run_id:
        w.set_metric("run_id", args.run_id)
    if notes:
        w.set_metric("notes", notes)
    w.flush()
    w.mark_done(scanned, complete, extra={"notes": len(notes)} if notes else None)

    print("scan_code done: pages=%d routes=%d findings=%d complete=%s"
          % (len(pages), len(declared), len(w.findings),
             "true" if complete else "false"))
    for note in notes:
        print("  note: %s" % note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
