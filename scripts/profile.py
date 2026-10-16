#!/usr/bin/env python3
"""profile - platform profile loader for bug-sweep scanners.

Profiles are JSON (the managed runtime has no PyYAML; stdlib json only).
A profile carries the platform-specific facts (directory layout, entry files,
placeholder word table, ownership rules, thresholds); the scanners carry the
kernel judgments. This split is what keeps the scripts project-agnostic.

Loading order:
  1. built-in <skill-dir>/profiles/<id>.json
  2. deep-merged user override <work-dir>/bug-sweep.profile.json (user wins)
  3. schema validation (missing key -> exit 2 with the JSON path)

auto detection scores: any_files +10 each, all_files +20 (complete set),
content_markers +5 each, plus detect.priority. Highest unique score wins;
a tie or an all-zero field exits 2 and demands an explicit --profile.
Standard library only; importing this module has no side effects.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(os.path.dirname(HERE), "profiles")

SKIP_DIRS = {".git", "node_modules", "miniprogram_npm", "out", "dist", "build",
             "target", "vendor", "coverage", ".venv", "venv", "__pycache__",
             ".next", ".nuxt", ".idea", ".vscode"}

REQUIRED_TOP = ["schema_version", "id", "display_name", "detect", "roots",
                "ownership", "layers", "signals", "cron", "thresholds"]
REQUIRED_DETECT = ["priority", "any_files", "all_files", "content_markers"]
REQUIRED_SIGNALS = ["placeholder_words", "sensitive_field_patterns",
                    "async_call_hints", "key_consts", "timer_hints",
                    "domain_fields"]
REQUIRED_THRESHOLDS = ["fn_lines", "max_nesting", "mccabe",
                       "dup_min_lines", "dup_min_similarity"]

ANY_FILE_SCORE = 10
ALL_FILES_SCORE = 20
MARKER_SCORE = 5
_MAX_MARKER_FILES = 4000
_MAX_MARKER_BYTES = 400000


class ProfileError(Exception):
    """Any profile problem that must abort with exit 2 (never a silent guess)."""


class Profile(object):
    """Read-only view over a merged profile dict."""

    def __init__(self, data, source_path):
        self._data = data
        self.source_path = source_path

    def get(self, key, default=None):
        return self._data.get(key, default)

    @property
    def id(self):
        return self._data.get("id", "")

    @property
    def display_name(self):
        return self._data.get("display_name", "")

    def layers(self):
        """Layer descriptors sorted by order."""
        return sorted(self._data.get("layers", []),
                      key=lambda l: l.get("order", 99))

    def enabled_layers(self):
        return [l["id"] for l in self.layers() if l.get("enabled_by_default")]

    def layer_meta(self, layer_id):
        for l in self.layers():
            if l.get("id") == layer_id:
                return l
        return None

    def skip_reason(self, layer_id):
        meta = self.layer_meta(layer_id)
        return (meta or {}).get("skip_reason", "profile 未启用该层")

    def dump(self):
        return json.dumps(self._data, ensure_ascii=False, indent=2,
                          sort_keys=True)


# ------------------------------------------------------------------ loading --

def _deep_merge(base, over):
    out = dict(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _validate(data, where):
    if not isinstance(data, dict):
        raise ProfileError("%s: profile 顶层必须是 JSON 对象" % where)
    for key in REQUIRED_TOP:
        if key not in data:
            raise ProfileError("%s: 缺少必填键 '%s'" % (where, key))
    detect = data["detect"]
    for key in REQUIRED_DETECT:
        if key not in detect:
            raise ProfileError("%s: detect 缺少必填键 '%s'" % (where, key))
    for key in REQUIRED_SIGNALS:
        if key not in data["signals"]:
            raise ProfileError("%s: signals 缺少必填键 '%s'" % (where, key))
    for key in REQUIRED_THRESHOLDS:
        if key not in data["thresholds"]:
            raise ProfileError("%s: thresholds 缺少必填键 '%s'" % (where, key))
    if not isinstance(data["layers"], list) or not data["layers"]:
        raise ProfileError("%s: layers 必须是非空数组" % where)
    for layer in data["layers"]:
        for key in ("id", "order", "display_name", "enabled_by_default"):
            if key not in layer:
                raise ProfileError("%s: layers[] 缺少必填键 '%s'" % (where, key))
    if not isinstance(data["ownership"], list):
        raise ProfileError("%s: ownership 必须是数组" % where)
    for rule in data["ownership"]:
        if "pattern" not in rule or "layer" not in rule:
            raise ProfileError("%s: ownership[] 每项需含 pattern 与 layer" % where)
    words = data["signals"]["placeholder_words"]
    if not isinstance(words, list):
        raise ProfileError("%s: signals.placeholder_words 必须是数组" % where)


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ProfileError("%s: JSON 解析失败（第 %d 行 %d 列）：%s"
                           % (path, e.lineno, e.colno, e.msg))
    except OSError as e:
        raise ProfileError("%s: 无法读取：%s" % (path, e))


def default_override_path(work_dir):
    """User override convention: <work-dir>/bug-sweep.profile.json (or None)."""
    if not work_dir:
        return None
    p = os.path.join(work_dir, "bug-sweep.profile.json")
    return p if os.path.exists(p) else None


def list_profile_ids(profile_dir=None):
    profile_dir = profile_dir or PROFILE_DIR
    if not os.path.isdir(profile_dir):
        return []
    return sorted(f[:-5] for f in os.listdir(profile_dir)
                  if f.endswith(".json"))


def load(pid, root, override=None, profile_dir=None):
    """Load profile <pid>, deep-merge the user override, validate, return Profile."""
    profile_dir = profile_dir or PROFILE_DIR
    if not pid or not str(pid).strip():
        raise ProfileError("profile id 不能为空")
    pid = str(pid).strip()
    if pid == "auto":
        raise ProfileError("load() 需要显式 profile id；auto 探测请用 detect()")
    path = os.path.join(profile_dir, pid + ".json")
    if not os.path.exists(path):
        raise ProfileError(
            "profile '%s' 不存在（查找路径 %s）。可用 id：%s"
            % (pid, path, ", ".join(list_profile_ids(profile_dir)) or "(无)"))
    data = _read_json(path)
    if override:
        if not os.path.exists(override):
            raise ProfileError("override 文件不存在：%s" % override)
        data = _deep_merge(data, _read_json(override))
    _validate(data, path)
    return Profile(data, path)


# ------------------------------------------------------------------ detect --

class Candidate(object):
    def __init__(self, pid, score, hits):
        self.id = pid
        self.score = score
        self.hits = hits

    def __repr__(self):
        return "Candidate(%s, score=%d, hits=%s)" % (self.id, self.score,
                                                     ",".join(self.hits))


def _iter_marker_files(root):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            p = os.path.join(dirpath, name)
            try:
                if os.path.getsize(p) > _MAX_MARKER_BYTES:
                    continue
            except OSError:
                continue
            yield p
            count += 1
            if count >= _MAX_MARKER_FILES:
                return


def detect(root, profile_dir=None):
    """Score every built-in profile against <root>. Highest unique score wins."""
    profile_dir = profile_dir or PROFILE_DIR
    if not os.path.isdir(root):
        raise ProfileError("project root 不存在：%s" % root)
    texts = []
    for p in _iter_marker_files(root):
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                texts.append(f.read())
        except OSError:
            continue
    blob = "\n".join(texts)
    candidates = []
    for pid in list_profile_ids(profile_dir):
        try:
            data = _read_json(os.path.join(profile_dir, pid + ".json"))
            detect_cfg = data.get("detect", {})
        except ProfileError:
            continue
        score = 0
        hits = []
        for f in detect_cfg.get("any_files", []):
            if os.path.exists(os.path.join(root, f)):
                score += ANY_FILE_SCORE
                hits.append(f)
        all_files = detect_cfg.get("all_files", [])
        if all_files and all(os.path.exists(os.path.join(root, f))
                             for f in all_files):
            score += ALL_FILES_SCORE
            hits.extend(all_files)
        for marker in detect_cfg.get("content_markers", []):
            if marker and marker in blob:
                score += MARKER_SCORE
                hits.append("marker:%s" % marker)
        # Priority is a TIE-BREAKER among profiles that actually matched
        # something. Adding it unconditionally would make a high-priority
        # profile (wechat-miniprogram) win on unrelated projects with zero
        # hits - the silent-fallback behaviour contract 5.6 forbids.
        if score > 0:
            score += int(detect_cfg.get("priority", 0) or 0)
            candidates.append(Candidate(pid, score, hits))
    return candidates


def detect_or_fail(root, profile_dir=None):
    """Return the winning profile id or raise ProfileError (exit 2 upstream)."""
    candidates = detect(root, profile_dir=profile_dir)
    if not candidates:
        raise ProfileError(
            "未识别平台（auto 探测全部 0 命中）。可显式指定已有 profile，"
            "或用 --profile generic-polyglot 只跑内核判据。"
            "可用 id：%s" % ", ".join(list_profile_ids(profile_dir)))
    best = max(c.score for c in candidates)
    winners = [c for c in candidates if c.score == best]
    if len(winners) > 1:
        raise ProfileError(
            "auto 探测并列最高（%d 分）：%s。请用 --profile 显式指定，"
            "不静默猜测。"
            % (best, "; ".join("%s（命中 %s）" % (c.id, ",".join(c.hits) or "无")
                               for c in winners)))
    return winners[0]


# --------------------------------------------------------------------- CLI --

def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    ap = argparse.ArgumentParser(
        prog="profile.py",
        description="bug-sweep profile 加载 / 探测工具（JSON，零依赖）")
    ap.add_argument("--profile", default=None,
                    help="profile id 或 auto（自动探测）")
    ap.add_argument("--project-root", default=".", help="项目根目录")
    ap.add_argument("--work-dir", default=None,
                    help="工作目录（用户覆盖文件 <work-dir>/bug-sweep.profile.json）")
    ap.add_argument("--override", default=None,
                    help="用户覆盖 JSON（深合并，用户值优先）")
    ap.add_argument("--detect", action="store_true",
                    help="只跑 auto 探测并打印全部候选得分")
    ap.add_argument("--dump-effective", action="store_true",
                    help="打印合并后的最终配置")
    ap.add_argument("--selftest", action="store_true",
                    help="自检：加载全部内置 profile（无网络、无副作用）")
    args = ap.parse_args(argv)

    try:
        if args.selftest:
            ids = list_profile_ids()
            if not ids:
                raise ProfileError("未找到任何内置 profile：%s" % PROFILE_DIR)
            for pid in ids:
                prof = load(pid, args.project_root)
                if prof.id != pid:
                    raise ProfileError("%s: id 字段与文件名不一致" % pid)
            print("OK profile selftest: %d profiles loaded (%s)"
                  % (len(ids), ", ".join(ids)))
            return 0
        if args.detect:
            cands = detect(args.project_root)
            if not cands:
                print("no candidate scored above zero")
                return 0
            for c in sorted(cands, key=lambda c: -c.score):
                print("%-22s score=%-4d hits=%s"
                      % (c.id, c.score, ",".join(c.hits) or "-"))
            return 0
        if not args.profile:
            ap.error("必须指定 --profile <id|auto>、--detect 或 --selftest")
        override = args.override or default_override_path(args.work_dir)
        if args.profile == "auto":
            winner = detect_or_fail(args.project_root)
            print("auto selected: %s (hits: %s)"
                  % (winner.id, ",".join(winner.hits) or "-"))
            prof = load(winner.id, args.project_root, override=override)
        else:
            prof = load(args.profile, args.project_root, override=override)
        if args.dump_effective:
            print(prof.dump())
        else:
            print("loaded: %s (%s) from %s"
                  % (prof.id, prof.display_name, prof.source_path))
        return 0
    except ProfileError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
