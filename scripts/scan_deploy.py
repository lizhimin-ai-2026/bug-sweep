#!/usr/bin/env python3
"""scan_deploy - runtime layer + schedule layer (merged, one script, two layers).

Both layers read the same two inputs (source tree + deployment snapshot), so
they share a single load_sources() pass. The merge removes the old hidden
file-order dependency where the schedule scanner needed a JSON file produced
by the client scanner.

Runtime checks: ghost functions, undeployed units, config drift (with the
false-positive class 8 derivation caveat), env reconciliation with the
two-tier severity split, dual config-channel mismatch, hardcoded secret-like
literals (offset + length + type ONLY - never a value fragment), write-guard
bypass switches, un-awaited async candidates.

Schedule checks: three-way reconciliation (local declaration / live snapshot /
function body), cron field counts, and the event-parameter exemption.

Usage:
    python scan_deploy.py --root <src-dir> --live <snapshot.json>
                          [--layers runtime,schedule] [--work-dir D]
                          [--profile P]

Outputs (under <work-dir>/out, overwrite mode):
    findings_runtime.csv | metrics_runtime.json | _done_runtime.txt
    findings_schedule.csv | metrics_schedule.json | _done_schedule.txt

Exit codes: 0 complete / 2 input error (missing root, missing or corrupt
snapshot - never silently degrades to "local only").
Standard library only; importing this module has no side effects.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweeplib as S  # noqa: E402
import profile as P  # noqa: E402

# Kernel-wide generic patterns (no project facts live here).
SECRET_NAME_RE = re.compile(r"(KEY|SECRET|TOKEN|APPID|APP_KEY|PASSWORD|AESKEY)",
                            re.I)
SECRET_LITERAL_RE = re.compile(
    r"""(?:key|secret|token|appkey|app_key|appid|app_id|aeskey|password|passwd)"""
    r"""\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{16,})['"]""", re.I)
GUARD_NAME_RE = re.compile(r"\b(dry[_-]?run|preview|read[_-]?only)\b", re.I)
BYPASS_NAME_RE = re.compile(r"\b([A-Za-z0-9_]*(?:_EXECUTE|FORCE|OVERRIDE|BYPASS))\b")
ENV_JS_RE = re.compile(r"process\.env\.([A-Za-z0-9_]+)|process\.env\[['\"]([A-Za-z0-9_]+)['\"]\]")
ENV_PY_RE = re.compile(
    r"os\.environ\.get\(\s*['\"]([A-Za-z0-9_]+)['\"]"
    r"|os\.getenv\(\s*['\"]([A-Za-z0-9_]+)['\"]"
    r"|os\.environ\[\s*['\"]([A-Za-z0-9_]+)['\"]\s*\]")
ASYNC_EXCLUDE_START = ("return", "console.", "if", "for", "while", "switch",
                       "const", "let", "var", "}", "{", "else", "try", "//")
DUAL_CHANNEL_RE = re.compile(r"env_file|BaseSettings|pydantic.*Settings|class .*Settings")
PY_ENV_READ_RE = re.compile(r"os\.getenv|os\.environ")


# ------------------------------------------------------------------- sources --

class Unit(object):
    """One deployable unit (a directory with an entry file)."""

    def __init__(self, name, path):
        self.name = name
        self.path = path
        self.entry_path = None
        self.entry_src = ""
        self.config = {}
        self.files = []      # (relpath, text)


def _entry_name(prof):
    entries = prof.get("entry_files", []) or []
    return entries[0] if entries else "index.js"


def load_sources(root, prof):
    """Read the source tree once; both layers consume the result."""
    root = os.path.abspath(root)
    runtime_root_name = (prof.get("roots", {}) or {}).get("runtime", "") or ""
    base = os.path.join(root, runtime_root_name) if runtime_root_name else root
    if not os.path.isdir(base):
        base = root
    entry = _entry_name(prof)
    units = {}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in P.SKIP_DIRS]
        if entry in filenames:
            name = os.path.basename(dirpath)
            u = Unit(name, dirpath)
            u.entry_path = os.path.join(dirpath, entry)
            u.entry_src = S.read_text(u.entry_path)
            cfg_path = os.path.join(dirpath, "config.json")
            if os.path.exists(cfg_path):
                try:
                    u.config = json.loads(S.read_text(cfg_path))
                except json.JSONDecodeError:
                    u.config = {}
            units[name] = u
        for fn in filenames:
            if fn.endswith(S.SKIP_FILE_SUFFIXES):
                continue
            p = os.path.join(dirpath, fn)
            if os.path.getsize(p) > 2 * 1024 * 1024:
                continue
            try:
                text = S.read_text(p)
            except OSError:
                continue
            if dirpath in [u.path for u in units.values()]:
                for u in units.values():
                    if u.path == dirpath:
                        u.files.append((S.rel_path(p, root), text))
                        break
            else:
                key = os.path.basename(dirpath) or "_root"
                u = units.get(key)
                if u is None:
                    u = Unit(key, dirpath)
                    units[key] = u
                u.files.append((S.rel_path(p, root), text))
    return root, units


def load_live(path):
    """Load the deployment snapshot. Missing/corrupt = exit 2, no degradation."""
    if not path:
        raise S.InputError("缺少云端实况快照（--live）。该层不降级为「只扫本地」——"
                           "降级会让幽灵函数漏检，属静默退化")
    if not os.path.exists(path):
        raise S.InputError("云端实况快照不存在：%s。修法：用云平台控制台或 MCP "
                           "采集后落盘（envKeys 只取变量名，不取值）" % path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise S.InputError("%s: 快照 JSON 解析失败（第 %d 行 %d 列）：%s"
                           % (path, e.lineno, e.colno, e.msg))
    fns = data.get("functions", data) if isinstance(data, dict) else data
    if not isinstance(fns, list):
        raise S.InputError("%s: 快照缺少 functions 数组" % path)
    out = {}
    for f in fns:
        if isinstance(f, dict) and f.get("name"):
            out[f["name"]] = f
    return out


# ------------------------------------------------------------------- runtime --

def _env_has_default(src, name, is_py):
    """The four fallback spellings (JS) plus the Python getenv-default forms."""
    if is_py:
        for pat in (r"os\.environ\.get\(\s*['\"]%s['\"]\s*," % re.escape(name),
                    r"os\.getenv\(\s*['\"]%s['\"]\s*," % re.escape(name),
                    r"os\.environ\[\s*['\"]%s['\"]\s*\]\s*or\b" % re.escape(name)):
            if re.search(pat, src):
                return True
        return False
    for pat in (r"process\.env\.%s\s*\|\|" % re.escape(name),
                r"process\.env\.%s\s*!==?" % re.escape(name),
                r"process\.env\.%s\s*===?" % re.escape(name),
                r"process\.env\.%s\s*\?" % re.escape(name)):
        if re.search(pat, src):
            return True
    return False


def _envs_used(src, is_py):
    names = set()
    if is_py:
        for m in ENV_PY_RE.finditer(src):
            names.add(m.group(1) or m.group(2) or m.group(3))
    else:
        for m in ENV_JS_RE.finditer(src):
            names.add(m.group(1) or m.group(2))
    return names


def scan_runtime(root, units, live, prof, work_dir, source="scan_deploy.py"):
    w = S.LayerWriter(os.path.join(work_dir, "out"), "runtime", source,
                      profile=prof)
    scanned = 0
    complete = True
    hints = prof.get("signals", {}).get("async_call_hints", []) or []

    local_names = set(units)
    live_names = set(live)
    for name in sorted(live_names - local_names):
        w.add("cloud.ghost_fn", name, "cloud/%s" % name, "P1", "本地缺源码",
              "云端已部署但本地工程无该单元：%s" % name,
              "云端函数 %s（ModTime=%s）在本地源码树中无对应目录"
              % (name, live[name].get("modTime", "-")), 0)
    for name in sorted(local_names - live_names):
        w.add("cloud.undeployed", name, "%s/%s" % (name, _entry_name(prof)),
              "P2", "云端未部署", "本地有源码但云端函数列表无此项：%s" % name,
              "本地目录存在，云端 %d 个函数中无同名项" % len(live_names), 0)

    for name in sorted(local_names & live_names):
        u = units[name]
        lf = live[name]
        scanned += 1
        entry_rel = S.rel_path(u.entry_path, root) if u.entry_path else name
        src = "\n".join(t for _, t in u.files)
        is_py = entry_rel.endswith(".py")

        # config drift (local declaration vs live reality)
        for field, live_key in (("timeout", "timeout"), ("memory", "memory"),
                                ("runtime", "runtime")):
            lv = u.config.get(field)
            rv = lf.get(live_key)
            if lv is None or rv is None:
                continue
            if str(lv) != str(rv):
                w.add("config.drift", name, entry_rel, "P2", "配置漂移",
                      "%s 的 %s 本地声明与云端实况不一致" % (name, field),
                      "本地 %s / 云端 %s；不一致本身不是缺陷——需再推导"
                      "「云端值 < 实际需求」才报（误报第八类）"
                      % (lv, rv), 0)

        # env reconciliation (two tiers; env_has_default four spellings)
        envs = _envs_used(src, is_py)
        live_envs = set(lf.get("envKeys") or [])
        missing = sorted(envs - live_envs)
        hard = [e for e in missing
                if not _env_has_default(src, e, is_py)
                and SECRET_NAME_RE.search(e)]
        soft = [e for e in missing if e not in hard]
        if hard:
            w.add("env.missing", name, entry_rel, "P1", "环境变量缺配",
                  "%s 的密钥类环境变量云端未配置" % name,
                  "云端未配：%s（无代码兜底，功能直接不可用）"
                  % ",".join(hard), 0)
        if soft:
            with_default = [e for e in soft if _env_has_default(src, e, is_py)]
            w.add("env.not_set", name, entry_rel, "P2", "环境变量未显式配置",
                  "%s 有环境变量云端未配（功能可用，靠代码兜底）" % name,
                  "云端未配：%s；其中 %d 个有显式默认值，其余为开关/阈值类"
                  % (",".join(soft), len(with_default)), 0)

        # dual config channel (pydantic env_file vs os.environ, no load_dotenv)
        if is_py and DUAL_CHANNEL_RE.search(src) and PY_ENV_READ_RE.search(src) \
                and "load_dotenv" not in src:
            w.add("env.channel_mismatch", name, entry_rel, "P2",
                  "配置读取通道错位",
                  "%s 同时存在 Settings(env_file) 与 os.environ 两条读取通道，"
                  "且无 load_dotenv()" % name,
                  "报「代码未接好」不报「配置缺失」——.env 不写 os.environ，"
                  "os.getenv 永远为空（误报第十类）", 0)

        # hardcoded secret-like literal: NEVER a value fragment
        for m in SECRET_LITERAL_RE.finditer(src):
            w.add("secret.literal", name, entry_rel, "P0", "硬编码疑似密钥",
                  "%s 源码出现疑似密钥字面量" % name,
                  "offset=%d 长度=%d 类型=key_like_literal（值不落盘，"
                  "只报位置与类型）" % (m.start(), len(m.group(1))), 0)

        # write-guard bypass
        if GUARD_NAME_RE.search(src):
            for m in BYPASS_NAME_RE.finditer(src):
                w.add("guard.bypass", m.group(1), entry_rel, "P1",
                      "写保护可被旁路",
                      "发现只读默认值闸的同时存在旁路开关 %s" % m.group(1),
                      "该开关可让防误触闸失效，一旦误设任何调用都会直接写库"
                      "（误报第十三类）", 0)

        # un-awaited async candidates (JS family only)
        if not is_py and hints:
            for rel, text in u.files:
                for ln, line in enumerate(text.split("\n"), 1):
                    s = line.strip()
                    if not s or s.startswith(ASYNC_EXCLUDE_START):
                        continue
                    if "await" in s or "=>" in s:
                        continue
                    for hint in hints:
                        if hint in s:
                            w.add("src.async_unawaited", rel, rel, "P2",
                                  "疑似未 await",
                                  "异步调用可能未 await：%s" % hint,
                                  "行 %d 命中 %s；一律写疑似——漏写（缺陷）vs "
                                  "故意不阻断（设计取舍）由人定夺"
                                  "（误报第二类）" % (ln, hint), ln)
                            break

    w.set_metric("scanned_units", scanned)
    w.set_metric("local_units", sorted(local_names))
    w.set_metric("live_units", sorted(live_names))
    w.flush()
    w.mark_done(scanned=scanned, complete=complete)
    return w


# ------------------------------------------------------------------ schedule --

def _local_triggers(units, root):
    """Collect trigger declarations from unit config.json files."""
    out = []
    for name in sorted(units):
        u = units[name]
        trigs = u.config.get("triggers")
        if not isinstance(trigs, list):
            continue
        for i, t in enumerate(trigs):
            if not isinstance(t, dict):
                continue
            tname = t.get("name") or "%s#%d" % (name, i + 1)
            out.append({"name": tname, "unit": name,
                        "cron": t.get("cron") or t.get("schedule") or "",
                        "type": t.get("type", "")})
    return out


def scan_schedule(root, units, live, prof, work_dir, source="scan_deploy.py"):
    w = S.LayerWriter(os.path.join(work_dir, "out"), "schedule", source,
                      profile=prof)
    scanned = 0
    complete = True
    cron_fields = int((prof.get("cron", {}) or {}).get("fields", 0) or 0)
    timer_hints = prof.get("signals", {}).get("timer_hints", []) or []
    log_values = (prof.get("evidence", {}) or {}).get(
        "schedule_log_values", {}) or {}

    local = _local_triggers(units, root)
    live_trigs = []
    for fname in sorted(live):
        for i, t in enumerate(live[fname].get("triggers") or []):
            if isinstance(t, dict):
                tname = t.get("name") or "%s#%d" % (fname, i + 1)
                live_trigs.append({"name": tname, "unit": fname,
                                   "cron": t.get("cron") or t.get("schedule")
                                   or "", "type": t.get("type", "")})
    local_by = {t["name"]: t for t in local}
    live_by = {t["name"]: t for t in live_trigs}
    scanned = len(set(local_by) | set(live_by))

    for tname in sorted(set(live_by) - set(local_by)):
        w.add("trigger.cloud_only", tname, "cloud/%s" % live_by[tname]["unit"],
              "P1", "云端有本地无声明",
              "触发器 %s 只存在于云端，本地没有声明" % tname,
              "换机器重新部署就丢；本地声明表 %d 项 / 云端 %d 项"
              % (len(local_by), len(live_by)), 0)
    for tname in sorted(set(local_by) - set(live_by)):
        w.add("trigger.local_only", tname,
              "%s/config.json" % local_by[tname]["unit"], "P2",
              "本地声明云端无",
              "触发器 %s 本地有声明、云端列表没有" % tname,
              "可能在另一侧平台跑，也可能真没生效——查日志是唯一硬证据"
              "（误报第四类：「列表为空」≠「不存在」）", 0)
        if log_values:
            w.add("schedule.log_evidence_needed", tname,
                  "%s/config.json" % local_by[tname]["unit"], "INFO",
                  "需日志证据", "触发器 %s 需要日志证据佐证" % tname,
                  "日志取值判据：%s"
                  % "; ".join("%s=%s" % (k, v)
                              for k, v in sorted(log_values.items())), 0)

    for tname in sorted(set(local_by) & set(live_by)):
        cron = local_by[tname].get("cron") or ""
        if cron and cron_fields:
            parts = cron.split()
            if len(parts) != cron_fields:
                w.add("cron.malformed", tname,
                      "%s/config.json" % local_by[tname]["unit"], "P2",
                      "cron 段数不符", "触发器 %s 的 cron 段数不符 profile 约定"
                      % tname,
                      "cron=「%s」共 %d 段，期望 %d 段（profile.cron.fields）"
                      % (cron, len(parts), cron_fields), 0)

    # function body has timer branch but no trigger on either side
    for name in sorted(units):
        u = units[name]
        src = "\n".join(t for _, t in u.files)
        if not any(h in src for h in timer_hints):
            continue
        if name in live_by.values().__class__ and False:
            continue
        has_trigger = (name in [t["unit"] for t in local]
                       or name in [t["unit"] for t in live_trigs])
        if has_trigger:
            continue
        if re.search(r"(?:exports\.main|def main|main_handler|function main)"
                     r"\s*[=(]\s*\(?[^)]*\bevent\b", src):
            continue  # event-driven entry: no type branch needed (exemption)
        w.add("trigger.body_no_handler", name,
              S.rel_path(u.entry_path, root) if u.entry_path else name,
              "P1", "定时分支无触发器",
              "%s 函数体含定时分支，但本地与云端都没有触发器" % name,
              "这段代码没人调用；入口参数含 event 的函数已豁免"
              "（调度层判据）", 0)

    w.set_metric("local_triggers", len(local))
    w.set_metric("live_triggers", len(live_trigs))
    w.flush()
    w.mark_done(scanned=scanned, complete=complete)
    return w


# ---------------------------------------------------------------------- CLI --

def _selftest():
    import shutil
    import tempfile
    td = tempfile.mkdtemp(prefix="bugsweep-selftest-")
    try:
        root = os.path.join(td, "svc")
        os.makedirs(os.path.join(root, "unit_a"))
        with open(os.path.join(root, "unit_a", "index.js"), "w",
                  encoding="utf-8") as f:
            f.write("const K = process.env.APP_KEY || 'x';\n"
                    "exports.main = async (event) => { return K; };\n")
        live = os.path.join(td, "live.json")
        with open(live, "w", encoding="utf-8") as f:
            json.dump({"functions": [
                {"name": "unit_a", "timeout": 3, "envKeys": ["APP_KEY"]},
                {"name": "ghost_unit", "timeout": 3, "envKeys": []},
            ]}, f)
        prof = P.load("generic-polyglot", td)
        r, units = load_sources(root, prof)
        live_fns = load_live(live)
        w = scan_runtime(r, units, live_fns, prof, td)
        sigs = sorted(f["signal"] for f in w.findings)
        assert "cloud.ghost_fn" in sigs, sigs
        assert "cloud.undeployed" not in sigs, sigs
        # secret gate must fire on a value fragment
        try:
            S.assert_no_secret("api_key: abcdef1234567890", "selftest")  # skillcheck:allow - deliberate gate test vector, not a credential
            raise AssertionError("secret gate did not fire")
        except S.SecretLeak:
            pass
        print("OK scan_deploy selftest: runtime reconcile + secret gate "
              "(signals: %s)" % ",".join(sigs))
        return 0
    finally:
        shutil.rmtree(td, ignore_errors=True)


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    S.stdout_utf8()
    if "--selftest" in argv:
        return _selftest()
    ap = argparse.ArgumentParser(
        prog="scan_deploy.py",
        description="bug-sweep 运行时层 + 调度层扫描（本地源码 vs 部署实况）")
    ap.add_argument("--root", required=True, help="源码根目录（必填）")
    ap.add_argument("--live", required=True, help="部署实况快照 JSON（必填）")
    ap.add_argument("--layers", default="runtime,schedule",
                    help="要跑的层：runtime / schedule / runtime,schedule")
    ap.add_argument("--work-dir", required=True,
                    help="工作目录（必填，产物落 <work-dir>/out）")
    ap.add_argument("--profile", default="generic-polyglot", help="profile id")
    ap.add_argument("--run-id", default="", help="运行 ID（记录用）")
    ap.add_argument("--selftest", action="store_true", help="内置自检")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    layers = [x.strip() for x in args.layers.split(",") if x.strip()]
    for x in layers:
        if x not in ("runtime", "schedule"):
            sys.stderr.write("error: --layers 只接受 runtime/schedule：%s\n" % x)
            return 2
    try:
        if not os.path.isdir(args.root):
            raise S.InputError("源码根目录不存在：%s" % args.root)
        prof = P.load(args.profile, args.root)
        live = load_live(args.live)
        root, units = load_sources(args.root, prof)
        total = 0
        if "runtime" in layers:
            w = scan_runtime(root, units, live, prof, args.work_dir)
            total += len(w.findings)
            print("scan_deploy[runtime] done: %d findings -> %s"
                  % (len(w.findings), w.csv_path))
        if "schedule" in layers:
            w = scan_schedule(root, units, live, prof, args.work_dir)
            total += len(w.findings)
            print("scan_deploy[schedule] done: %d findings -> %s"
                  % (len(w.findings), w.csv_path))
        print("scan_deploy done: %d findings across %s"
              % (total, ",".join(layers)))
        return 0
    except S.InputError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2
    except P.ProfileError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
