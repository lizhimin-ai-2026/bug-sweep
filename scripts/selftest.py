#!/usr/bin/env python3
"""selftest - stage-1 basic gate for bug-sweep (simplified edition).

Scope (stage 1 v0.1 only; the heavy fixture-reading gate 11 and the AST
entry-guard gate 10 arrive with stage 3):
  1. module-selftest   sweeplib / profile / scan_code / scan_api --selftest
  2. fingerprint       independent recomputation of the contract formula
  3. profiles          all 7 built-in profiles load, id matches file name
  4. scan_code-dry     minimal temp client tree: happy path assertions
  5. scan_code-broken  corrupt route manifest -> P0 + complete=false
  6. entry-guard       missing required args -> exit 2 with a readable error

The scan_code dry runs build a minimal synthetic tree in a temp dir. They are
link checks (the scanner runs end to end and emits the expected signals);
they are NOT judgment claims - the C16 smoke fixtures are the evidence for
that, and they belong to stage 3.

Usage:
    python selftest.py --skill-dir <D> [--work-dir <W>] [--only a,b] [--verbose]

Outputs: report under <work-dir> (default: a fresh temp dir). The skill
directory itself is never written to. Exit 0 = all cases pass, 1 = failure.
Standard library only; importing this module has no side effects.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweeplib as S  # noqa: E402
import profile as P  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

CASES = []


def case(name, title):
    def deco(fn):
        CASES.append((name, title, fn))
        return fn
    return deco


def _run(script, args):
    """Run a sibling script; return (returncode, stdout, stderr)."""
    p = subprocess.run([PY, os.path.join(HERE, script)] + args,
                       capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


# ------------------------------------------------------------------- cases --

@case("module-selftest", "四个脚本 --selftest 全部 exit 0")
def _c_module_selftest(ctx):
    for script in ("sweeplib.py", "profile.py", "scan_code.py", "scan_api.py"):
        rc, out, err = _run(script, ["--selftest"])
        if rc != 0:
            return "%s --selftest exit %d: %s" % (script, rc, err.strip())
        if not out.strip():
            return "%s --selftest produced no output" % script
    return None


@case("fingerprint", "指纹公式独立复算（黄金向量 + 行号排除）")
def _c_fingerprint(ctx):
    # Independent golden vector: sha1 of the hand-joined contract payload.
    golden = "dbd3b53bbbd3e495"
    got = S.fingerprint("deep", "app/svc_a.py", "deep.silent.empty_catch",
                        "svc_a.load_config")
    if got != golden:
        return "fingerprint drifted: got %s want %s" % (got, golden)
    moved = S.fingerprint("deep", "app/svc_a.py:99", "deep.silent.empty_catch",
                          "svc_a.load_config")
    if moved != got:
        return "line number changed the fingerprint (%s vs %s)" % (got, moved)
    return None


@case("profiles", "7 个内置 profile 全部加载且 id 与文件名一致")
def _c_profiles(ctx):
    import profile as P
    ids = P.list_profile_ids(ctx["profiles_dir"])
    if len(ids) < 7:
        return "expected at least 7 profiles, found %d: %s" % (
            len(ids), ", ".join(ids))
    for pid in ids:
        try:
            prof = P.load(pid, ctx["skill_dir"], profile_dir=ctx["profiles_dir"])
        except P.ProfileError as e:
            return "load %s failed: %s" % (pid, e)
        if prof.id != pid:
            return "%s: id field %r does not match file name" % (pid, prof.id)
    return None


def _build_client_tree(root, manifest_text):
    """Minimal synthetic client tree for the scan_code dry runs."""
    mp = os.path.join(root, "miniprogram")
    pages = os.path.join(mp, "pages")
    home = os.path.join(pages, "home")
    broken = os.path.join(pages, "broken")
    utils = os.path.join(mp, "utils")
    for d in (home, broken, utils):
        os.makedirs(d, exist_ok=True)
    with open(os.path.join(root, ".gitignore"), "w", encoding="utf-8") as f:
        f.write("ignored_*.bak\n")
    with open(os.path.join(root, "project.config.json"), "w",
              encoding="utf-8") as f:
        json.dump({"packOptions": {"ignore": ["half_*.bak"]}}, f)
    with open(os.path.join(mp, "app.json"), "w", encoding="utf-8") as f:
        f.write(manifest_text)
    for name in ("index.js", "index.wxml", "index.json", "index.wxss"):
        with open(os.path.join(home, name), "w", encoding="utf-8") as f:
            f.write("// %s\n" % name)
    with open(os.path.join(home, "index.js"), "a", encoding="utf-8") as f:
        f.write("const api = require('../../utils/api.js');\n"
                "api.used_api('x');\n"
                "const remark = '待补充';\n"
                "// TODO: finish this page\n"
                "console.log(remark);\n")
    with open(os.path.join(broken, "index.js"), "w", encoding="utf-8") as f:
        f.write("// broken page: missing wxml/json/wxss\n")
    with open(os.path.join(utils, "api.js"), "w", encoding="utf-8") as f:
        f.write("function self_called() { return self_called(); }\n"
                "function used_api(x) { return x; }\n"
                "function dead_api(x) { return x; }\n"
                "self_called();\n"
                "module.exports = { used_api: used_api, dead_api: dead_api };\n")
    with open(os.path.join(home, "stale.bak"), "w", encoding="utf-8") as f:
        f.write("stale\n")
    with open(os.path.join(home, "ignored_1.bak"), "w", encoding="utf-8") as f:
        f.write("covered by gitignore\n")
    with open(os.path.join(home, "half_1.bak"), "w", encoding="utf-8") as f:
        f.write("covered by only one of two ignore rules\n")
    return mp


def _read_csv(path):
    import csv
    with open(path, "r", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _hash_dir(root):
    """name -> sha256 for every file under root (idempotency comparisons)."""
    import hashlib
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root).replace("\\", "/")
            with open(p, "rb") as f:
                out[rel] = hashlib.sha256(f.read()).hexdigest()
    return out


def _build_db_project(tmp, name="proj"):
    """Minimal synthetic project: pyproject.toml + app.db with one planted
    whole-word placeholder. Self-contained on purpose - the C16 fixtures
    and their bidirectional assertions belong to stage 3."""
    import sqlite3
    proj = os.path.join(tmp, name)
    os.makedirs(proj, exist_ok=True)
    with open(os.path.join(proj, "pyproject.toml"), "w",
              encoding="utf-8") as f:
        f.write("[project]\nname = \"selftest-proj\"\n")
    db = os.path.join(proj, "app.db")
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, remark TEXT)")
    con.execute("INSERT INTO notes (remark) VALUES ('ok'), ('待补充')")
    con.commit()
    con.close()
    with open(os.path.join(proj, "app.py"), "w", encoding="utf-8") as f:
        f.write("def main():\n    return 1\n\n\nif __name__ == '__main__':\n"
                "    main()\n")
    return proj


@case("scan_code-dry", "scan_code 干跑：最小临时客户端树全链路")
def _c_scan_code_dry(ctx):
    root = os.path.join(ctx["tmp"], "dry")
    os.makedirs(root, exist_ok=True)
    _build_client_tree(root, json.dumps(
        {"pages": ["pages/home", "pages/ghost"]}, ensure_ascii=False))
    work = os.path.join(root, "work")
    rc, out, err = _run("scan_code.py", [
        "--root", os.path.join(root, "miniprogram"),
        "--project-root", root,
        "--work-dir", work,
        "--profile", "wechat-miniprogram"])
    if rc != 0:
        return "scan_code exit %d: %s" % (rc, err.strip())
    csv_path = os.path.join(work, "out", "findings_client.csv")
    if not os.path.exists(csv_path):
        return "findings csv missing"
    rows = _read_csv(csv_path)
    signals = {}
    for r in rows:
        signals.setdefault(r["signal"], []).append(r)
    for want in ("page.incomplete", "route.dangling", "deadcode.fn",
                 "bak.file", "client.placeholder_hit", "todo.marker"):
        if want not in signals:
            return "expected signal %s not emitted (got %s)" % (
                want, sorted(signals))
    dead = [r["anchor"] for r in signals["deadcode.fn"]]
    if not any("dead_api" in a for a in dead):
        return "deadcode.fn did not flag the unreferenced export: %s" % dead
    for a in dead:
        if "used_api" in a or "self_called" in a:
            return "deadcode.fn false positive (module-internal call rule): %s" % a
    baks = signals["bak.file"]
    if not any(r["severity"] == "P1" for r in baks):
        return "uncovered backup file should be P1"
    if not any(r["severity"] == "P2" for r in baks):
        return "half-covered backup file should be P2"
    done = S.read_done(os.path.join(work, "out"), "client")
    if not done or done.get("complete") != "true":
        return "completion marker missing or incomplete: %s" % (done,)
    ph = [r for r in signals["client.placeholder_hit"]]
    if not ph or ph[0]["severity"] != "INFO":
        return "source placeholder hit must be INFO"
    todo = signals["todo.marker"]
    if not todo or todo[0]["severity"] != "P2":
        return "todo marker must be P2"
    return None


@case("scan_code-broken", "scan_code 干跑：路由 manifest 损坏 → P0 + complete=false")
def _c_scan_code_broken(ctx):
    root = os.path.join(ctx["tmp"], "broken")
    os.makedirs(root, exist_ok=True)
    _build_client_tree(root, "{ this is not json ")
    work = os.path.join(root, "work")
    rc, out, err = _run("scan_code.py", [
        "--root", os.path.join(root, "miniprogram"),
        "--project-root", root,
        "--work-dir", work,
        "--profile", "wechat-miniprogram"])
    if rc != 0:
        return "scan_code exit %d: %s" % (rc, err.strip())
    rows = _read_csv(os.path.join(work, "out", "findings_client.csv"))
    hit = [r for r in rows if r["signal"] == "route.manifest_broken"]
    if not hit:
        return "corrupt manifest did not produce route.manifest_broken"
    if hit[0]["severity"] != "P0":
        return "route.manifest_broken must be P0, got %s" % hit[0]["severity"]
    done = S.read_done(os.path.join(work, "out"), "client")
    if not done or done.get("complete") != "false":
        return "corrupt manifest must mark complete=false: %s" % (done,)
    return None


@case("entry-guard", "入口守卫：缺必填参数 → exit 2 且 stderr 可读")
def _c_entry_guard(ctx):
    checks = [
        ("scan_api.py", ["--work-dir", ctx["tmp"]]),
        ("scan_code.py", ["--root", ctx["tmp"]]),
        ("scan_data.py", ["--work-dir", ctx["tmp"]]),
        ("scan_deploy.py", ["--root", ctx["tmp"], "--work-dir", ctx["tmp"]]),
        ("sweep.py", ["--project-root", ctx["tmp"]]),
        ("sweep.py", ["--work-dir", ctx["tmp"]]),
        ("ledger.py", []),
        ("undo.py", ["restore", "--work-dir", ctx["tmp"]]),
        ("undo.py", ["backup", "--work-dir", ctx["tmp"], "--root", ctx["tmp"]]),
    ]
    for script, args in checks:
        rc, out, err = _run(script, args)
        if rc != 2:
            return "%s with missing required args exited %d (want 2)" % (
                script, rc)
        if not err.strip():
            return "%s exited 2 without a readable error message" % script
    return None


@case("sweep-dry", "sweep 干跑：最小临时工程全链路（data + deep 实跑 + 台账）")
def _c_sweep_dry(ctx):
    proj = _build_db_project(ctx["tmp"])
    work = os.path.join(ctx["tmp"], "sweep")
    rc, out, err = _run("sweep.py", [
        "--project-root", proj, "--work-dir", work,
        "--profile", "generic-python"])
    if rc != 0:
        return "sweep exit %d: %s" % (rc, err.strip()[:200])
    if not os.path.exists(os.path.join(work, "ledger.csv")):
        return "ledger.csv missing after sweep"
    if "[deep] ok:" not in out:
        return "deep layer did not run (deep_scan.py present): %s" % out[-200:]
    rows = _read_csv(os.path.join(work, "out", "findings_data.csv"))
    if len(rows) != 1 or rows[0]["signal"] != "data.placeholder_hit":
        return "unexpected data findings: %s" % [r["signal"] for r in rows]
    if rows[0]["path"] != "app.db":
        return "finding path must be project-root relative, got %r" \
            % rows[0]["path"]
    deep_csv = os.path.join(work, "out", "findings_deep.csv")
    if not os.path.exists(deep_csv):
        return "deep findings csv missing after sweep"
    return None


@case("sweep-abort", "sweep 整批作废：complete=false → exit 1 且不产出台账")
def _c_sweep_abort(ctx):
    proj = _build_db_project(ctx["tmp"], "proj-abort")
    work = os.path.join(ctx["tmp"], "sweep-abort")
    rc, out, err = _run("sweep.py", [
        "--project-root", proj, "--work-dir", work,
        "--profile", "generic-python", "--table", "nosuch", "--required"])
    if rc != 1:
        return "abort path exited %d (want 1): %s" % (rc, err.strip()[:200])
    if os.path.exists(os.path.join(work, "ledger.csv")):
        return "ledger must NOT be written when a layer is incomplete"
    if "不产出台账" not in out:
        return "abort message missing the batch-void rationale"
    return None


@case("ledger-idempotent", "台账幂等：两个全新工作目录的同输入 sweep 产物逐字节一致")
def _c_ledger_idempotent(ctx):
    proj = _build_db_project(ctx["tmp"], "proj-idem")
    digests = []
    for i in (1, 2):
        work = os.path.join(ctx["tmp"], "sweep-idem%d" % i)
        rc, out, err = _run("sweep.py", [
            "--project-root", proj, "--work-dir", work,
            "--profile", "generic-python"])
        if rc != 0:
            return "sweep run %d exit %d: %s" % (i, rc, err.strip()[:200])
        digests.append(_hash_dir(work))
    if digests[0] != digests[1]:
        diff = [k for k in set(digests[0]) | set(digests[1])
                if digests[0].get(k) != digests[1].get(k)]
        return "products differ across identical fresh-state runs: %s" % diff
    return None


@case("gate10-entry-guard", "门禁10：AST 入口守卫（main + __main__ 守卫 + 模块级无可执行语句）")
def _c_gate10(ctx):
    import ast
    scripts_dir = os.path.join(ctx["skill_dir"], "scripts")
    # pure initializers allowed at module level (idempotent, side-effect free)
    pure_calls = {"re.compile", "os.path.dirname", "os.path.abspath",
                  "os.path.join", "os.path.exists"}
    for name in sorted(os.listdir(scripts_dir)):
        if not name.endswith(".py"):
            continue
        tree = ast.parse(open(os.path.join(scripts_dir, name),
                              encoding="utf-8").read(), name)
        has_main = any(isinstance(n, ast.FunctionDef) and n.name == "main"
                       for n in tree.body)
        has_guard = any(
            isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
            and isinstance(n.test.left, ast.Name)
            and n.test.left.id == "__name__" for n in tree.body)
        if not (has_main and has_guard):
            return "%s: 缺 main() 或 __main__ 守卫" % name
        for node in tree.body:
            k = type(node).__name__
            if k in ("Import", "ImportFrom", "FunctionDef", "ClassDef",
                     "If", "Assign", "AnnAssign"):
                continue
            if k == "Expr":
                v = node.value
                if isinstance(v, ast.Constant):
                    continue                      # module docstring
                f = getattr(v, "func", None)
                if f is not None and ast.unparse(f) == "sys.path.insert":
                    continue                      # sibling-import bootstrap
                return "%s: 模块级可执行表达式 %s" % (name, ast.unparse(v)[:60])
            return "%s: 模块级 %s 语句" % (name, k)
        # assignments may only call pure initializers
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            for sub in ast.walk(value) if value is not None else []:
                if isinstance(sub, ast.Call):
                    fn = ast.unparse(sub.func)
                    if fn not in pure_calls:
                        return ("%s: 模块级赋值调用非纯函数 %s"
                                % (name, fn))
    return None


def _layer_group(signal, path, prof):
    """Gate-11 layer_group: deep.* fixed; else ownership, else producing."""
    if str(signal).startswith("deep."):
        return "deep"
    producing = {"data": "data", "api": "api", "cloud": "runtime",
                 "config": "runtime", "env": "runtime", "secret": "runtime",
                 "guard": "runtime", "src": "runtime", "trigger": "schedule",
                 "cron": "schedule", "schedule": "schedule",
                 "page": "client", "route": "client", "deadcode": "client",
                 "bak": "client", "share": "client", "todo": "client",
                 "ledger": "ledger"}
    default = producing.get(str(signal).split(".")[0], "")
    prof_dict = prof.dump_data() if hasattr(prof, "dump_data") else {}
    return S.resolve_layer(path, prof_dict, default)


@case("gate11-c16", "门禁11：C16 三 fixture 双向断言（显式 profile 轮 + auto 轮）")
def _c_gate11(ctx):
    import csv as _csv
    fixtures = os.path.join(ctx["skill_dir"], "tests", "fixtures")
    cases = (("smoke-python", "generic-python"),
             ("smoke-node", "generic-node"),
             ("smoke-go", "generic-go"))
    for fx, expect_profile in cases:
        root = os.path.join(fixtures, fx)
        manifest_path = os.path.join(root, "manifest.json")
        if not os.path.exists(manifest_path):
            return "%s: manifest.json 缺失" % fx
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        work = os.path.join(ctx["tmp"], "gate11-%s" % fx)
        # round 1: explicit profile, bidirectional assertion
        rc, out, err = _run("sweep.py", [
            "--project-root", root, "--work-dir", work,
            "--profile", expect_profile])
        if rc != 0:
            return "%s: sweep exit %d: %s" % (fx, rc, err.strip()[:200])
        ledger_path = os.path.join(work, "ledger.csv")
        if not os.path.exists(ledger_path):
            return "%s: ledger.csv missing" % fx
        with open(ledger_path, "r", encoding="utf-8-sig") as f:
            rows = list(_csv.DictReader(f))
        actual = {}
        for r in rows:
            if r["severity"] in ("P0", "P1", "P2"):
                actual[r["fingerprint"]] = (r["signal"], r["anchor"],
                                            r["severity"])
        prof = P.load(expect_profile, root)
        expected = {}
        for p in manifest.get("planted", []):
            lg = _layer_group(p["signal"], p["path"], prof)
            fp = S.fingerprint(lg, p["path"], p["signal"], p["anchor"])
            expected[fp] = (p["signal"], p["anchor"])
        missing = [v for k, v in expected.items() if k not in actual]
        if missing:
            return ("%s: 漏报 %d 条（%s）。检查 profile=%s 的判据配置"
                    % (fx, len(missing),
                       "; ".join("%s@%s" % m for m in missing[:4]),
                       expect_profile))
        unplanned = [v for k, v in actual.items() if k not in expected]
        if unplanned:
            return ("%s: 计划外条目 %d 条（%s）。信噪比崩溃：检查阈值/"
                    "整词匹配/入口判定"
                    % (fx, len(unplanned),
                       "; ".join("%s@%s[%s]" % v for v in unplanned[:4])))
        for fb in manifest.get("forbidden", []):
            lg = _layer_group(fb["signal"], fb["path"], prof)
            fp = S.fingerprint(lg, fb["path"], fb["signal"], fb["anchor"])
            if fp in actual:
                return ("%s: forbidden 命中 %s（%s @ %s）——防误报失守"
                        % (fx, fb["signal"], fb["anchor"], fb["path"]))
        # round 2: auto must SELECT the expected profile (not merely not fail)
        rc, out, err = _run("profile.py",
                            ["--project-root", root, "--profile", "auto"])
        if rc != 0:
            return "%s: auto 轮 exit %d: %s" % (fx, rc, err.strip()[:160])
        if ("auto selected: %s " % expect_profile) not in out:
            return ("%s: auto 选中错误（期望 %s）：%s"
                    % (fx, expect_profile, out.strip().split("\n")[0]))
    return None


@case("gate13-placeholder", "门禁13：占位词整词约束（无 <3 字 / 无 TODO 三词 / 波利略岛回归）")
def _c_gate13(ctx):
    import glob
    words = []
    for p in sorted(glob.glob(os.path.join(ctx["profiles_dir"], "*.json"))):
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        for w in data.get("signals", {}).get("placeholder_words", []):
            if len(w) < 3:
                return "%s: placeholder_words 含 <3 字条目 %r" % (
                    os.path.basename(p), w)
            if w in ("TODO", "FIXME", "XXX"):
                return "%s: placeholder_words 含禁用标记词 %r" % (
                    os.path.basename(p), w)
            words.append(w)
    # whole-word regression: a single char inside a real place name
    if S.whole_word_hits("菲律宾波利略岛（Polillo）", ["略"]) != []:
        return "单字「略」在长词内部被误判为占位词命中"
    if S.whole_word_hits("值=待补充；待查证", words) == []:
        return "整词占位词未被命中（词表 %s）" % words
    return None


@case("undo-lifecycle", "undo 生命周期：备份→篡改→校验→恢复→重入拒绝")
def _c_undo_lifecycle(ctx):
    root = os.path.join(ctx["tmp"], "undo-proj")
    work = os.path.join(ctx["tmp"], "undo-work")
    for d in (root, work):
        os.makedirs(d, exist_ok=True)
    target = os.path.join(root, "a.js")
    with open(target, "w", encoding="utf-8") as f:
        f.write("original A\n")
    rc, out, err = _run("undo.py", ["backup", "--root", root,
                                    "--work-dir", work,
                                    "--paths", "a.js,b.js"])
    if rc != 0:
        return "backup exit %d: %s" % (rc, err.strip()[:200])
    undo_dir = os.path.join(work, "undo")
    sid = sorted(os.listdir(undo_dir))[-1]
    with open(target, "w", encoding="utf-8") as f:
        f.write("TAMPERED\n")
    with open(os.path.join(root, "b.js"), "w", encoding="utf-8") as f:
        f.write("created after backup\n")
    rc, out, err = _run("undo.py", ["verify", "--snapshot", sid,
                                    "--work-dir", work])
    if rc != 1:
        return "verify should exit 1 after tampering, got %d" % rc
    rc, out, err = _run("undo.py", ["restore", "--snapshot", sid,
                                    "--work-dir", work])
    if rc != 0:
        return "restore exit %d: %s" % (rc, err.strip()[:200])
    if open(target, encoding="utf-8").read() != "original A\n":
        return "restore did not recover the original content"
    if os.path.exists(os.path.join(root, "b.js")):
        return "manifest-recorded new file was not deleted on restore"
    rc, out, err = _run("undo.py", ["restore", "--snapshot", sid,
                                    "--work-dir", work])
    if rc != 2:
        return "re-restore must be refused with exit 2, got %d" % rc
    return None


# --------------------------------------------------------------------- CLI --

def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    S.stdout_utf8()
    ap = argparse.ArgumentParser(
        prog="selftest.py",
        description="bug-sweep 阶段1 基础门禁（精简版）")
    ap.add_argument("--skill-dir", default=os.path.dirname(HERE),
                    help="技能目录（缺省取脚本上级目录）")
    ap.add_argument("--work-dir", default=None,
                    help="报告落盘目录（缺省用临时目录，技能目录永不写入）")
    ap.add_argument("--only", default="",
                    help="只跑指定用例，逗号分隔")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    skill_dir = os.path.abspath(args.skill_dir)
    profiles_dir = os.path.join(skill_dir, "profiles")
    if not os.path.isdir(profiles_dir):
        sys.stderr.write("error: profiles 目录不存在：%s\n" % profiles_dir)
        return 2
    work_dir = args.work_dir or tempfile.mkdtemp(prefix="bugsweep-selftest-")
    os.makedirs(work_dir, exist_ok=True)
    only = set(x.strip() for x in args.only.split(",") if x.strip())

    ctx = {"skill_dir": skill_dir, "profiles_dir": profiles_dir,
           "work_dir": work_dir, "tmp": os.path.join(work_dir, "tmp")}
    os.makedirs(ctx["tmp"], exist_ok=True)

    selected = [c for c in CASES if not only or c[0] in only]
    unknown = only - set(c[0] for c in CASES)
    if unknown:
        sys.stderr.write("error: 未知用例 %s（可用：%s）\n"
                         % (", ".join(sorted(unknown)),
                            ", ".join(c[0] for c in CASES)))
        return 2

    results = []
    failures = 0
    for name, title, fn in selected:
        try:
            problem = fn(ctx)
        except Exception as e:  # a crash is a failure, never a pass
            problem = "异常：%s: %s" % (type(e).__name__, e)
        ok = problem is None
        failures += 0 if ok else 1
        results.append({"case": name, "title": title, "ok": ok,
                        "problem": problem})
        print("%s %-16s %s" % ("PASS" if ok else "FAIL", name, title))
        if not ok:
            print("       -> %s" % problem)

    report = {
        "stage": "v0.1",
        "skill_dir": skill_dir,
        "cases": results,
        "passed": len(results) - failures,
        "failed": failures,
    }
    with open(os.path.join(work_dir, "selftest_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    lines = ["# bug-sweep selftest 报告（阶段1 精简版）", "",
             "- skill_dir: %s" % skill_dir,
             "- 用例：%d 通过 / %d 失败" % (len(results) - failures, failures), ""]
    for r in results:
        lines.append("- [%s] %s %s" % ("x" if r["ok"] else " ", r["case"],
                                       r["title"]))
        if r["problem"]:
            lines.append("  - %s" % r["problem"])
    with open(os.path.join(work_dir, "selftest_report.md"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("selftest v0.1: %d/%d passed, report at %s"
          % (len(results) - failures, len(results), work_dir))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
