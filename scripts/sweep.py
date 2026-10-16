#!/usr/bin/env python3
"""sweep - bug-sweep orchestrator: dispatch the enabled layers, then aggregate.

Runs the per-layer scanners as subprocesses (each keeps its own main() and
exit-code contract), then builds the ledger through ledger.py. Orchestration
is deterministic scheduling only - sweep itself makes no judgments.

Layer inputs and their absence (never a silent degrade):
  data      --db or <root>/<roots.db>          missing file -> skipped+note
  api       --base (no default domain exists)  no --base    -> skipped+note
  runtime   --root + --live snapshot           no snapshot  -> skipped+note
  schedule  same invocation as runtime (merged scanner, one read of sources)
  client    <root>/<roots.client>              missing dir  -> skipped+note
  deep      deep_scan.py                       script absent-> skipped+note

Completion discipline: after the layers run, every layer that produced a
findings csv must carry a complete _done marker. Any missing marker or
complete=false aborts BEFORE the ledger ("rather void the whole batch than
ship half a ledger") - exit 1, no ledger.

Usage:
    python sweep.py --project-root <dir> --work-dir <dir>
                    [--profile <id|auto>] [--db <path>] [--base <url>]
                    [--live <snapshot.json>] [--paths-file <json>]
                    [--id-range 1-280] [--not-found-probe <path>] [--rate 1.2]
                    [--table T]... [--domain-fields f1,f2]
                    [--constraints-file <json>] [--expect-count table=n]...
                    [--required] [--layers data,api,...] [--run-id X]

Exit codes: 0 all ran layers complete, ledger built /
1 a ran layer is incomplete (no ledger) / 2 input error (bad profile,
missing project root, auto detection ambiguous).
Standard library only; importing this module has no side effects.
"""
import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweeplib as S  # noqa: E402
import profile as P  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def _run(script, args):
    """Run a sibling scanner; return (returncode, stdout, stderr)."""
    try:
        p = subprocess.run([PY, os.path.join(HERE, script)] + args,
                           capture_output=True, text=True, timeout=1800)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 2, "", "%s timed out after 1800s" % script


def _first_line(text, limit=160):
    for line in (text or "").split("\n"):
        line = line.strip()
        if line:
            return line[:limit]
    return ""


class LayerResult(object):
    def __init__(self, layer):
        self.layer = layer
        self.status = "pending"   # ok / skipped / failed
        self.detail = ""
        self.exit_code = None


def resolve_live_snapshot(args, prof, project_root, work_dir):
    """--live wins; then the profile's live_snapshot.path convention."""
    if args.live:
        return args.live if os.path.isabs(args.live) \
            else os.path.join(project_root, args.live)
    spec = (prof.get("live_snapshot", {}) or {}).get("path", "")
    if spec:
        for base in (work_dir, project_root):
            cand = os.path.join(base, spec)
            if os.path.exists(cand):
                return cand
    return None


def run_data(args, prof, project_root, work_dir, run_id):
    db = args.db or os.path.join(
        project_root, (prof.get("roots", {}) or {}).get("db", "app.db"))
    if not os.path.exists(db):
        return LayerResult("data"), None
    cmd = ["scan_data.py", "--db", db, "--project-root", project_root,
           "--work-dir", work_dir, "--profile", prof.id]
    cmd += sum([["--table", t] for t in args.table], [])
    if args.domain_fields:
        cmd += ["--domain-fields", args.domain_fields]
    if args.constraints_file:
        cmd += ["--constraints-file", args.constraints_file]
    cmd += sum([["--expect-count", e] for e in args.expect_count], [])
    if args.required:
        cmd += ["--required"]
    if run_id:
        cmd += ["--run-id", run_id]
    rc, out, err = _run(cmd[0], cmd[1:])
    res = LayerResult("data")
    res.exit_code = rc
    if rc == 0:
        res.status = "ok"
        res.detail = _first_line(out)
    else:
        res.status = "failed"
        res.detail = _first_line(err) or _first_line(out)
    return res, cmd


def run_api(args, prof, project_root, work_dir, run_id):
    if not args.base:
        res = LayerResult("api")
        res.status = "skipped"
        res.detail = ("接口层需 --base 显式指定（契约禁止内置默认域名）；"
                      "需要时补 --base 重跑")
        return res, None
    cmd = ["scan_api.py", "--base", args.base, "--work-dir", work_dir,
           "--profile", prof.id]
    if args.paths_file:
        cmd += ["--paths-file", args.paths_file]
    if args.id_range:
        cmd += ["--id-range", args.id_range]
    if args.not_found_probe:
        cmd += ["--not-found-probe", args.not_found_probe]
    if args.expect_total is not None:
        cmd += ["--expect-total", str(args.expect_total)]
    if args.rate:
        cmd += ["--rate", str(args.rate)]
    if run_id:
        cmd += ["--run-id", run_id]
    rc, out, err = _run(cmd[0], cmd[1:])
    res = LayerResult("api")
    res.exit_code = rc
    if rc == 0:
        res.status = "ok"
        res.detail = _first_line(out)
    else:
        res.status = "failed"
        res.detail = _first_line(err) or _first_line(out)
    return res, cmd


def run_deploy(args, prof, project_root, work_dir, run_id, layers):
    live = resolve_live_snapshot(args, prof, project_root, work_dir)
    if not live:
        res = LayerResult("+".join(layers))
        res.status = "skipped"
        res.detail = ("运行时/调度层需部署实况快照（--live 或按 profile "
                      "live_snapshot.path 放置）；缺失不降级为「只扫本地」"
                      "——降级会让幽灵函数漏检，属静默退化")
        return res, None
    roots = prof.get("roots", {}) or {}
    root = args.root or os.path.join(project_root,
                                     roots.get("runtime", "") or "")
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        res = LayerResult("+".join(layers))
        res.status = "failed"
        res.detail = "源码根目录不存在：%s" % root
        return res, None
    cmd = ["scan_deploy.py", "--root", root, "--live", live,
           "--layers", ",".join(layers), "--work-dir", work_dir,
           "--profile", prof.id]
    if run_id:
        cmd += ["--run-id", run_id]
    rc, out, err = _run(cmd[0], cmd[1:])
    res = LayerResult("+".join(layers))
    res.exit_code = rc
    if rc == 0:
        res.status = "ok"
        res.detail = _first_line(out)
    else:
        res.status = "failed"
        res.detail = _first_line(err) or _first_line(out)
    return res, cmd


def run_client(args, prof, project_root, work_dir, run_id):
    roots = prof.get("roots", {}) or {}
    client = roots.get("client", "")
    if not client:
        res = LayerResult("client")
        res.status = "skipped"
        res.detail = "profile 未配置 roots.client，客户端层不可用"
        return res, None
    cdir = os.path.join(project_root, client)
    if not os.path.isdir(cdir):
        res = LayerResult("client")
        res.status = "skipped"
        res.detail = "客户端目录不存在：%s" % cdir
        return res, None
    cmd = ["scan_code.py", "--root", cdir, "--project-root", project_root,
           "--work-dir", work_dir, "--profile", prof.id]
    if run_id:
        cmd += ["--run-id", run_id]
    rc, out, err = _run(cmd[0], cmd[1:])
    res = LayerResult("client")
    res.exit_code = rc
    if rc == 0:
        res.status = "ok"
        res.detail = _first_line(out)
    else:
        res.status = "failed"
        res.detail = _first_line(err) or _first_line(out)
    return res, cmd


def run_deep(args, prof, project_root, work_dir, run_id):
    script = os.path.join(HERE, "deep_scan.py")
    if not os.path.exists(script):
        res = LayerResult("deep")
        res.status = "skipped"
        res.detail = "deep_scan.py 未随附（阶段3 交付），深度四类未执行"
        return res, None
    cmd = ["deep_scan.py", "--root", project_root,
           "--kinds", "deadcode,dependency,complexity,silent",
           "--work-dir", work_dir, "--profile", prof.id]
    if run_id:
        cmd += ["--run-id", run_id]
    rc, out, err = _run(cmd[0], cmd[1:])
    res = LayerResult("deep")
    res.exit_code = rc
    if rc == 0:
        res.status = "ok"
        res.detail = _first_line(out)
    else:
        res.status = "failed"
        res.detail = _first_line(err) or _first_line(out)
    return res, cmd


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    S.stdout_utf8()
    if "--selftest" in argv:
        ap = argparse.ArgumentParser(prog="sweep.py")
        ap.add_argument("--project-root", default=".")
        ap.add_argument("--work-dir", default=".")
        ap.add_argument("--profile", default=None)
        ap.add_argument("--layers", default="")
        ap.parse_args(argv)
        print("OK sweep selftest: module imports cleanly, CLI parses, "
              "no network at import time")
        return 0
    ap = argparse.ArgumentParser(
        prog="sweep.py",
        description="bug-sweep 编排入口：派发启用层并汇总台账")
    ap.add_argument("--project-root", required=True, help="项目根目录（必填）")
    ap.add_argument("--work-dir", required=True, help="工作目录（必填）")
    ap.add_argument("--profile", default=None,
                    help="profile id 或 auto（自动探测）")
    ap.add_argument("--root", default=None,
                    help="运行时层源码根（缺省取 profile roots.runtime）")
    ap.add_argument("--db", default=None, help="sqlite 数据库路径")
    ap.add_argument("--base", default=None, help="接口层 base URL")
    ap.add_argument("--live", default=None, help="部署实况快照 JSON")
    ap.add_argument("--paths-file", default=None)
    ap.add_argument("--id-range", default=None)
    ap.add_argument("--not-found-probe", default=None)
    ap.add_argument("--expect-total", type=int, default=None)
    ap.add_argument("--rate", type=float, default=None)
    ap.add_argument("--table", action="append", default=[])
    ap.add_argument("--domain-fields", default="")
    ap.add_argument("--constraints-file", default=None)
    ap.add_argument("--expect-count", action="append", default=[])
    ap.add_argument("--required", action="store_true")
    ap.add_argument("--layers", default="",
                    help="只跑指定层（逗号分隔），在 profile 启用集内再过滤")
    ap.add_argument("--run-id", default="")
    args = ap.parse_args(argv)

    project_root = os.path.abspath(args.project_root)
    work_dir = os.path.abspath(args.work_dir)
    if not os.path.isdir(project_root):
        sys.stderr.write("error: 项目根目录不存在：%s\n" % project_root)
        return 2
    os.makedirs(os.path.join(work_dir, "out"), exist_ok=True)

    # ---- profile (explicit or auto; never a silent guess) ----
    try:
        if not args.profile:
            sys.stderr.write("error: 必须指定 --profile <id|auto>\n")
            return 2
        if args.profile == "auto":
            winner = P.detect_or_fail(project_root)
            prof = P.load(winner.id, project_root)
            print("sweep: auto selected %s (hits: %s)"
                  % (winner.id, ",".join(winner.hits) or "-"))
        else:
            prof = P.load(args.profile, project_root)
    except P.ProfileError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2

    enabled = set(prof.enabled_layers())
    if args.layers:
        wanted = [x.strip() for x in args.layers.split(",") if x.strip()]
        unknown = [x for x in wanted if x not in
                   set(l.get("id") for l in prof.layers())]
        if unknown:
            sys.stderr.write("error: --layers 含未知层 %s（profile %s 的层："
                             "%s）\n" % (",".join(unknown), prof.id,
                                        ",".join(sorted(
                                            l.get("id") for l in prof.layers()))))
            return 2
        enabled = enabled & set(wanted)
    print("sweep: profile=%s root=%s work-dir=%s layers=%s"
          % (prof.id, project_root, work_dir,
             ",".join(sorted(enabled)) or "(none)"))

    results = []
    # data / api / client / deep are independent; runtime+schedule share one
    # scan_deploy invocation (merged scanner, single read of both sources).
    if "data" in enabled:
        res, _cmd = run_data(args, prof, project_root, work_dir, args.run_id)
        results.append(res)
    if "api" in enabled:
        res, _cmd = run_api(args, prof, project_root, work_dir, args.run_id)
        results.append(res)
    deploy_layers = [l for l in ("runtime", "schedule") if l in enabled]
    if deploy_layers:
        res, _cmd = run_deploy(args, prof, project_root, work_dir,
                               args.run_id, deploy_layers)
        results.append(res)
    if "client" in enabled:
        res, _cmd = run_client(args, prof, project_root, work_dir,
                               args.run_id)
        results.append(res)
    if "deep" in enabled:
        res, _cmd = run_deep(args, prof, project_root, work_dir, args.run_id)
        results.append(res)

    # ---- report + completion discipline ----
    out_dir = os.path.join(work_dir, "out")
    incomplete = []
    for res in results:
        if res.status == "skipped":
            print("[%s] skipped: %s" % (res.layer, res.detail))
            continue
        if res.status == "failed":
            print("[%s] FAILED (exit %s): %s"
                  % (res.layer, res.exit_code, res.detail))
            incomplete.append(res.layer)
            continue
        if res.status == "ok":
            for sub in res.layer.split("+"):
                mark = S.read_done(out_dir, sub)
                if mark is None:
                    print("[%s] ok (exit 0) 但缺 _done_%s.txt" % (res.layer, sub))
                    incomplete.append(sub)
                elif mark.get("complete") != "true":
                    print("[%s] ok (exit 0) 但标记 complete=false" % sub)
                    incomplete.append(sub)
                else:
                    print("[%s] ok: %s finding(s), complete=true"
                          % (sub, mark.get("findings", "?")))
            continue

    if incomplete:
        print("sweep aborted: 层 %s 未全部完成。按「宁可整批作废重跑，"
              "也不出半份台账」——不产出台账。" % ",".join(incomplete))
        return 1

    # ---- all complete: build the ledger (sweep owns the aggregation) ----
    rc, out, err = _run("ledger.py",
                        ["--work-dir", work_dir, "--profile", prof.id])
    for line in (out or "").split("\n"):
        if line.strip():
            print("ledger: %s" % line)
    if rc != 0:
        sys.stderr.write("error: ledger.py exit %d: %s\n"
                         % (rc, _first_line(err)))
        return 1
    print("sweep done: ledger at %s"
          % os.path.join(work_dir, "ledger.csv"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
