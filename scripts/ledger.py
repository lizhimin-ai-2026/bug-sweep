#!/usr/bin/env python3
"""ledger - finding aggregation, triage views and baseline diff.

Aggregates the per-layer findings_<layer>.csv products into one ledger,
deduplicates by fingerprint (the only dedup key - free text never enters
the fingerprint, so rewording or moving a line cannot break dedup), and
carries human decisions forward across runs.

Completion-marker discipline (team-lead ruling):
  every findings_<layer>.csv must be accompanied by _done_<layer>.txt.
  A missing marker, or complete=false, becomes a P1 "scan incomplete"
  entry in the ledger - never a silent "layer ran, 0 findings".

Views:
  ledger    full triage ledger (ledger.csv + ledger.md), decisions carried
            forward from the previous ledger.csv
  proposal  aggregated deep-scan evidence (3 suggestions + others); the
            script only aggregates, the model writes, the human decides
  diff      four buckets against --previous (new / persisting+age_runs /
            resolved / regressed) + a fresh baseline snapshot

Usage:
    python ledger.py --work-dir <D> [--sources a.csv,b.csv,...] [--profile P]
                     [--view ledger|proposal|diff]
                     [--previous <baseline.json>] [--out <f>]

Outputs (under <work-dir>, overwrite mode):
    ledger.csv | ledger.md | out/baseline_<run-id>.json
    diff view additionally: out/baseline_diff_<run-id>.md

Exit codes: 0 ok / 1 some layer incomplete (ledger still written) /
2 input error (no sources, bad columns, bad baseline, bad profile).
Standard library only; importing this module has no side effects.
"""
import argparse
import csv
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweeplib as S  # noqa: E402
import profile as P  # noqa: E402

SEVERITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "INFO": 3}
DEFAULT_LAYER_ORDER = ["data", "api", "runtime", "schedule", "client", "deep"]


# ------------------------------------------------------------------ loading --

def _read_csv_rows(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        missing = [c for c in S.FINDING_FIELDS if c not in header]
        extra = [c for c in header if c not in S.FINDING_FIELDS]
        if missing or extra:
            raise S.InputError(
                "%s 列契约不符：缺 %s；多 %s（期望 16 列：%s）"
                % (path, ",".join(missing) or "无", ",".join(extra) or "无",
                   ",".join(S.FINDING_FIELDS)))
        return [dict(r) for r in reader]


def load_findings(work_dir, sources):
    """Read every findings csv (explicit --sources or out/findings_*.csv)."""
    out_dir = os.path.join(work_dir, "out")
    paths = []
    if sources:
        for s in sources:
            s = s.strip()
            if s:
                paths.append(s if os.path.isabs(s)
                             else os.path.join(work_dir, s))
    else:
        if os.path.isdir(out_dir):
            paths = sorted(
                os.path.join(out_dir, f) for f in os.listdir(out_dir)
                if f.startswith("findings_") and f.endswith(".csv"))
    if not paths:
        raise S.InputError(
            "未找到任何 findings csv（%s 下无 findings_*.csv，且未指定 "
            "--sources）。没有输入就不产出台账——不谎报成功。" % out_dir)
    rows = []
    for p in paths:
        if not os.path.exists(p):
            raise S.InputError("sources 指定的文件不存在：%s" % p)
        for r in _read_csv_rows(p):
            r["_source_file"] = os.path.basename(p)
            rows.append(r)
    return rows, paths


def check_markers(work_dir, rows, w):
    """Completion-marker discipline. Returns (incomplete_layers, scanned)."""
    out_dir = os.path.join(work_dir, "out")
    layers_with_csv = set(r["layer"] for r in rows)
    incomplete = []
    for layer in sorted(layers_with_csv):
        info = S.read_done(out_dir, layer)
        if info is None:
            incomplete.append(layer)
            w.add("ledger.incomplete", layer, "", "P1", "扫描不完整",
                  "层 %s 有 findings csv 但缺完成标记" % layer,
                  "_done_%s.txt 缺失：该层可能中途崩溃，csv 不得被当作"
                  "「跑完了、0 条」的证据" % layer)
            continue
        if info.get("complete") != "true":
            incomplete.append(layer)
            w.add("ledger.incomplete", layer, "", "P1", "扫描不完整",
                  "层 %s 自报扫描不完整（complete=false）" % layer,
                  "标记内容：%s" % json.dumps(
                      {k: v for k, v in info.items() if k != "path"},
                      ensure_ascii=False))
            continue
        claimed = info.get("findings")
        if claimed is not None:
            actual = sum(1 for r in rows if r["layer"] == layer)
            if int(claimed) != actual:
                incomplete.append(layer)
                w.add("ledger.incomplete", layer, "", "P1", "扫描不完整",
                      "层 %s 完成标记数与 csv 行数不符" % layer,
                      "标记 findings=%s，csv 实际 %d 行" % (claimed, actual))
    # Markers claiming findings without a csv are equally damning.
    if os.path.isdir(out_dir):
        for f in sorted(os.listdir(out_dir)):
            if not (f.startswith("_done_") and f.endswith(".txt")):
                continue
            layer = f[len("_done_"):-len(".txt")]
            info = S.read_done(out_dir, layer) or {}
            if layer not in layers_with_csv and int(info.get("findings", 0) or 0) > 0:
                incomplete.append(layer)
                w.add("ledger.incomplete", layer, "", "P1", "扫描不完整",
                      "层 %s 完成标记声称有发现但 csv 缺失" % layer,
                      "标记 findings=%s，但 out/ 无 findings_%s.csv"
                      % (info.get("findings"), layer))
    return incomplete


def dedup(rows):
    """Merge rows sharing a fingerprint: sources join, severity is the max."""
    merged = {}
    order = []
    for r in rows:
        fp = r["fingerprint"]
        if fp not in merged:
            merged[fp] = dict(r)
            order.append(fp)
            continue
        keep = merged[fp]
        if (SEVERITY_RANK.get(r["severity"], 9)
                < SEVERITY_RANK.get(keep["severity"], 9)):
            keep["severity"] = r["severity"]
        srcs = [s for s in keep["source"].split(";") if s]
        if r["source"] and r["source"] not in srcs:
            srcs.append(r["source"])
        keep["source"] = ";".join(srcs)
    return [merged[fp] for fp in order]


def carry_decisions(rows, prev_ledger_csv, prev_baseline):
    """Carry decision/owner/note forward by fingerprint and load age_runs
    from the previous baseline snapshot (the single age source).

    _age = consecutive runs BEFORE this one; this run makes it _age + 1.
    """
    hints = []
    prev_ages = {}
    if prev_baseline and os.path.exists(prev_baseline):
        try:
            with open(prev_baseline, "r", encoding="utf-8") as f:
                base = json.load(f)
            for fnd in base.get("findings", []):
                prev_ages[fnd.get("fingerprint")] = int(
                    fnd.get("age_runs", 0) or 0)
        except (OSError, json.JSONDecodeError):
            prev_ages = {}
    if prev_ledger_csv and os.path.exists(prev_ledger_csv):
        prev = {}
        for r in _read_csv_rows(prev_ledger_csv):
            prev[r["fingerprint"]] = r
        for r in rows:
            old = prev.get(r["fingerprint"])
            if not old:
                continue
            for col in ("decision", "owner", "note"):
                if old.get(col) and not r.get(col):
                    r[col] = old[col]
    for r in rows:
        r["_age"] = prev_ages.get(r["fingerprint"], 0)
        if r["_age"] + 1 >= 3 and not r.get("decision"):
            hints.append(r)
    return rows, hints


# ------------------------------------------------------------------ ordering --

def _layer_order_map(prof):
    order = {}
    display = {}
    if prof is not None:
        for l in prof.layers():
            order[l.get("id")] = int(l.get("order", 99))
            display[l.get("id")] = l.get("display_name") or l.get("id")
    for i, lid in enumerate(DEFAULT_LAYER_ORDER):
        order.setdefault(lid, i + 1)
        display.setdefault(lid, lid)
    return order, display


def sort_rows(rows, prof):
    order, _display = _layer_order_map(prof)
    return sorted(rows, key=lambda r: (
        order.get(r["layer"], 99),
        SEVERITY_RANK.get(r["severity"], 9),
        r["path"], r["anchor"], r["fingerprint"]))


# -------------------------------------------------------------------- views --

def _input_digest(paths):
    """Content-derived run id (12 hex).

    Idempotency hard rule: the same input content must produce byte-identical
    products, so the run id may NOT come from wall-clock time or file mtimes
    (both drift when a scanner rewrites an unchanged csv). A digest of the
    input contents is stable across reruns and across work dirs.
    """
    h = hashlib.sha1()
    for p in sorted(paths):
        h.update(os.path.basename(p).encode("utf-8"))
        h.update(b"\x00")
        try:
            with open(p, "rb") as f:
                h.update(f.read())
        except OSError:
            h.update(b"<unreadable>")
        h.update(b"\x00")
    return h.hexdigest()[:12]


def newest_baseline(out_dir):
    """The newest out/baseline_*.json, or None (age source for the ledger)."""
    if not os.path.isdir(out_dir):
        return None
    cands = [os.path.join(out_dir, f) for f in os.listdir(out_dir)
             if f.startswith("baseline_") and f.endswith(".json")]
    if not cands:
        return None
    return max(cands, key=os.path.getmtime)


def write_ledger_csv(rows, path):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=S.FINDING_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in S.FINDING_FIELDS})


def write_ledger_md(rows, path, prof, run_id, incomplete, hints, carried):
    order, display = _layer_order_map(prof)
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    lines = [
        "# bug-sweep 台账（run %s）" % run_id, "",
        "- profile: %s｜signal schema: %s"
        % (prof.id if prof else "(未指定)", S.SIGNAL_SCHEMA_VERSION),
        "- 条目 %d（P0 %d / P1 %d / P2 %d / INFO %d）"
        % (len(rows), counts.get("P0", 0), counts.get("P1", 0),
           counts.get("P2", 0), counts.get("INFO", 0)), "",
    ]
    if incomplete:
        lines += ["> **扫描不完整**：%s。以下台账不构成完整结论，"
                  "按「宁可整批作废重跑，也不出半份台账」处理。"
                  % "、".join(sorted(set(incomplete))), ""]
    if carried:
        lines += ["- 已从上一轮台账承接 decision/owner/note %d 条。"
                  % carried, ""]
    by_layer = {}
    for r in rows:
        by_layer.setdefault(r["layer"], []).append(r)
    for lid in sorted(by_layer, key=lambda l: order.get(l, 99)):
        group = by_layer[lid]
        lines.append("## %s %s（%d 条）"
                     % (display.get(lid, lid), lid, len(group)))
        lines.append("")
        lines.append("| no | 级别 | signal | anchor | path | 症状 | 证据 |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for i, r in enumerate(group, 1):
            lines.append("| %s-%02d | %s | %s | %s | %s | %s | %s |" % (
                lid, i, r["severity"], r["signal"], r["anchor"],
                r["path"], r["symptom"], r["evidence"].replace("|", "\\|")))
        lines.append("")
    if hints:
        lines.append("## 高龄未处理提示")
        lines.append("")
        for r in hints:
            lines.append("- `%s` %s @ %s 已连续 %d 轮未处理。修，或在 note "
                         "里写清不修的原因——否则下一轮还会出现。"
                         % (r["signal"], r["anchor"], r["path"],
                            r.get("_age", 0) + 1))
        lines.append("")
    if not rows:
        lines += ["（本轮无条目。）", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def build_baseline(rows, prof, run_id):
    """Baseline snapshot: decided entries are excluded on purpose."""
    findings = []
    for r in rows:
        if r.get("decision"):
            continue
        if r["severity"] == "INFO":
            continue
        findings.append({
            "fingerprint": r["fingerprint"],
            "signal": r["signal"],
            "layer": r["layer"],
            "severity": r["severity"],
            "path": r["path"],
            "anchor": r["anchor"],
            "loc_line": int(r.get("loc_line", 0) or 0),
            "symptom": r.get("symptom", ""),
            "age_runs": int(r.get("_age", 0) or 0) + 1,
        })
    return {
        "run_id": run_id,
        "input_digest": run_id,
        "profile_id": prof.id if prof else "",
        "signal_schema_version": S.SIGNAL_SCHEMA_VERSION,
        "findings": findings,
    }


def view_diff(rows, previous, prof, run_id, out_dir):
    """Four buckets + age tracking. Returns (report_lines, baseline)."""
    prev_findings = {}
    stale = False
    if previous:
        try:
            with open(previous, "r", encoding="utf-8") as f:
                prev = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise S.InputError("previous 基线不可读：%s：%s" % (previous, e))
        if prev.get("signal_schema_version") != S.SIGNAL_SCHEMA_VERSION:
            stale = True
        for fnd in prev.get("findings", []):
            prev_findings[fnd.get("fingerprint")] = fnd
    cur = {}
    for r in rows:
        if r.get("decision") or r["severity"] == "INFO":
            continue
        cur[r["fingerprint"]] = r
    new, persisting, resolved, regressed = [], [], [], []
    for fp, r in cur.items():
        old = prev_findings.get(fp)
        if old is None:
            new.append(r)
            continue
        r["_diff_age"] = int(old.get("age_runs", 1) or 1) + 1
        persisting.append(r)
        if (SEVERITY_RANK.get(r["severity"], 9)
                < SEVERITY_RANK.get(old.get("severity"), 9)):
            regressed.append((old, r))
    for fp, old in prev_findings.items():
        if fp not in cur:
            resolved.append(old)
    persisting.sort(key=lambda r: -r.get("_diff_age", 1))
    lines = ["# 基线 diff（run %s）" % run_id, ""]
    if stale:
        lines += ["> **stale_baseline**：基线 signal_schema_version=%s 与当前 "
                  "%s 不一致，「已解决」结论不可信——先核对词表变更。"
                  % (prev.get("signal_schema_version"),
                     S.SIGNAL_SCHEMA_VERSION), ""]
    lines += [
        "- new %d｜persisting %d（含 age_runs）｜resolved %d｜regressed %d"
        % (len(new), len(persisting), len(resolved), len(regressed)), "",
        "## new（本轮新出现）", ""]
    lines += ["- %s %s @ %s（%s）" % (r["severity"], r["signal"], r["path"],
                                     r["anchor"]) for r in new] or ["- （无）"]
    lines += ["", "## persisting（连续存在，age_runs = 已连续轮数）", ""]
    lines += ["- age=%d %s %s @ %s（%s）"
              % (r.get("_diff_age", 1), r["severity"], r["signal"], r["path"],
                 r["anchor"]) for r in persisting] or ["- （无）"]
    lines += ["", "## resolved（上轮有、本轮无）", ""]
    lines += ["- %s %s @ %s（%s）"
              % (o.get("severity"), o.get("signal"), o.get("path"),
                 o.get("anchor")) for o in resolved] or ["- （无）"]
    lines += ["", "## regressed（两轮都有但严重度升了）", ""]
    lines += ["- %s→%s %s @ %s（%s）"
              % (o.get("severity"), r["severity"], r["signal"], r["path"],
                 r["anchor"]) for o, r in regressed] or ["- （无）"]
    lines.append("")
    aged = [r for r in persisting if r.get("_diff_age", 1) >= 3]
    if aged:
        lines += ["## 连续 3 轮以上未处理", ""]
        lines += ["- age=%d %s %s @ %s：修，或在 ledger.csv 的 note 里写清"
                  "不修的原因。" % (r["_diff_age"], r["signal"], r["path"],
                                   r["anchor"]) for r in aged]
        lines.append("")
    return lines


def view_proposal(rows):
    """Aggregated deep-scan evidence only; the model writes the proposal."""
    deep = [r for r in rows
            if str(r["signal"]).startswith("deep.")
            and r["severity"] in ("P0", "P1", "P2")]
    groups = {}
    for r in deep:
        g = groups.setdefault(r["signal"], {"count": 0, "sev": {}, "anchors": []})
        g["count"] += 1
        g["sev"][r["severity"]] = g["sev"].get(r["severity"], 0) + 1
        if len(g["anchors"]) < 3:
            g["anchors"].append(r["anchor"])
    ranked = sorted(groups.items(), key=lambda kv: (
        -kv[1]["count"],
        min(SEVERITY_RANK.get(s, 9) for s in kv[1]["sev"]),
        kv[0]))
    lines = ["# 架构优化建议书·证据聚合（脚本只聚合，建议书由模型生成、人拍板）",
             "", "- 深扫条目 %d 条，聚为 %d 组。" % (len(deep), len(groups)), ""]
    for i, (sig, g) in enumerate(ranked[:3], 1):
        sev_text = "/".join("%s×%d" % (s, n) for s, n in
                            sorted(g["sev"].items(),
                                   key=lambda kv: SEVERITY_RANK.get(kv[0], 9)))
        lines.append("%d. **%s**（%d 条，%s）样本锚点：%s"
                     % (i, sig, g["count"], sev_text,
                        "、".join(g["anchors"])))
    rest = ranked[3:]
    if rest:
        total = sum(g["count"] for _s, g in rest)
        lines.append("- **其他**：%d 组共 %d 条（%s）"
                     % (len(rest), total,
                        "、".join(s for s, _g in rest)))
    if not ranked:
        lines.append("（无 P0-P2 深扫条目。）")
    lines.append("")
    return lines


# --------------------------------------------------------------------- CLI --

def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    S.stdout_utf8()
    ap = argparse.ArgumentParser(
        prog="ledger.py",
        description="bug-sweep 台账汇总 / 建议书证据 / 基线 diff")
    ap.add_argument("--work-dir", required=True, help="工作目录（必填）")
    ap.add_argument("--sources", default="",
                    help="逗号分隔的 findings csv；缺省扫 out/findings_*.csv")
    ap.add_argument("--profile", default=None, help="profile id（层序与层名）")
    ap.add_argument("--view", default="ledger",
                    choices=["ledger", "proposal", "diff"])
    ap.add_argument("--previous", default=None,
                    help="上一轮基线 JSON（--view diff 时必填）")
    ap.add_argument("--out", default=None, help="ledger.csv 输出路径")
    ap.add_argument("--run-id", default="", help="覆盖自动生成的运行 ID")
    args = ap.parse_args(argv)

    work_dir = os.path.abspath(args.work_dir)
    if not os.path.isdir(work_dir):
        sys.stderr.write("error: 工作目录不存在：%s\n" % work_dir)
        return 2
    out_dir = os.path.join(work_dir, "out")
    try:
        prof = None
        if args.profile:
            prof = P.load(args.profile, work_dir)
        rows, paths = load_findings(work_dir, args.sources)
        run_id = args.run_id or _input_digest(paths)

        # 1) completion-marker discipline (P1 rows, never a silent zero)
        marker_w = S.LayerWriter(os.path.join(work_dir, "out"), "_markers",
                                 "ledger.py", profile=prof, clear=False)
        incomplete = check_markers(work_dir, rows, marker_w)

        # 2) dedup + decision carry-forward (age from the newest baseline)
        rows = dedup(rows)
        prev_ledger = os.path.join(work_dir, "ledger.csv")
        prev_base = args.previous or newest_baseline(out_dir)
        rows, hints = carry_decisions(rows, prev_ledger, prev_base)
        # 2b) terminal-state decisions leave the ledger entirely - the same
        #口径 as the baseline snapshot. A row the human marked
        # fixed/wontfix/duplicate must never be reported again (the "half
        # ledger" disease: triage by a ledger that still lists fixed bugs).
        # Placed AFTER carry_decisions so a decision typed into the previous
        # ledger.csv cannot re-introduce the row, and AFTER check_markers so
        # marker counts still compare against the raw csv rows.
        rows = [r for r in rows
                if str(r.get("decision", "")).strip().lower()
                not in ("fixed", "wontfix", "duplicate")]
        rows = sort_rows(rows, prof)
        all_rows = rows + marker_w.findings
        all_rows = sort_rows(all_rows, prof)

        os.makedirs(out_dir, exist_ok=True)
        if args.view == "proposal":
            text = "\n".join(view_proposal(rows))
            target = os.path.join(out_dir, "proposal_%s.md" % run_id)
            with open(target, "w", encoding="utf-8") as f:
                f.write(text)
            print(text)
            print("proposal evidence at %s" % target)
        elif args.view == "diff":
            if not args.previous:
                sys.stderr.write("error: --view diff 需要 --previous "
                                 "<baseline.json>\n")
                return 2
            lines = view_diff(rows, args.previous, prof, run_id, out_dir)
            target = os.path.join(out_dir, "baseline_diff_%s.md" % run_id)
            with open(target, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            print("\n".join(lines))
            print("diff report at %s" % target)
        else:
            csv_path = args.out or os.path.join(work_dir, "ledger.csv")
            write_ledger_csv(all_rows, csv_path)
            md_path = os.path.splitext(csv_path)[0] + ".md"
            carried = sum(1 for r in rows if r.get("decision"))
            write_ledger_md(all_rows, md_path, prof, run_id, incomplete,
                            hints, carried)
            print("ledger: %d entries (%d incomplete-marker P1) -> %s | %s"
                  % (len(all_rows), len(marker_w.findings), csv_path, md_path))

        # 3) fresh baseline snapshot every run (decided/INFO excluded)
        baseline = build_baseline(rows, prof, run_id)
        base_path = os.path.join(out_dir, "baseline_%s.json" % run_id)
        with open(base_path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, ensure_ascii=False, indent=2)
        print("baseline snapshot: %s (%d findings)"
              % (base_path, len(baseline["findings"])))
        return 1 if incomplete else 0
    except S.InputError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2
    except P.ProfileError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
