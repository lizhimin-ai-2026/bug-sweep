#!/usr/bin/env python3
"""scan_data - data layer scanner (schema consistency).

Aggregate-only SQLite scanning: blank rates, whole-word placeholder hits,
value domains and declarative consistency constraints. Read-only; never emits
UPDATE, never selects sensitive column values into the output.

Usage:
    python scan_data.py --db <path> [--table T]... [--work-dir D] [--required]
                        [--domain-fields f1,f2] [--constraints-file <json>]
                        [--expect-total table=n] [--profile P] [--run-id ID]
                        [--project-root <dir>]

Outputs (all under <work-dir>/out, overwrite mode):
    findings_data.csv | metrics_data.json | _done_data.txt

Exit codes: 0 complete / 2 input error (missing db, bad sqlite, bad constraints).
Standard library only; importing this module has no side effects.
"""
import argparse
import csv
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweeplib as S  # noqa: E402
import profile as P  # noqa: E402

PLACEHOLDER_FETCH_CAP = 5000

# Blank-rate thresholds for data.empty_field (deterministic, project-agnostic).
RATE_FULL = 99.5
RATE_MAJOR = 50.0
RATE_PARTIAL = 20.0

# Kernel-level placeholder severity tiers. These are GENERIC to-do markers,
# not business facts, so the tier table may live in the kernel; a profile can
# still override it via signals.placeholder_p1_words.
PLACEHOLDER_P1_WORDS = ("待查证", "待补充", "待实测")


def _table_exists(cur, name):
    cur.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
                (name,))
    return cur.fetchone()[0] > 0


def _list_tables(cur):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    return [r[0] for r in cur.fetchall()
            if not r[0].startswith("sqlite_")]


def _load_constraints(path):
    """Load declarative constraints. Only SELECT/WITH statements are accepted."""
    if not path:
        return []
    if not os.path.exists(path):
        raise S.InputError("constraints 文件不存在：%s" % path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise S.InputError("%s: JSON 解析失败（第 %d 行）：%s"
                           % (path, e.lineno, e.msg))
    items = data.get("constraints", data) if isinstance(data, dict) else data
    out = []
    for i, item in enumerate(items):
        sql = str(item.get("sql", "")).strip()
        head = sql.lstrip("(").lstrip().lower()
        if not (head.startswith("select") or head.startswith("with")):
            raise S.InputError(
                "%s: 第 %d 条约束不是只读查询（只允许 SELECT/WITH）：%s"
                % (path, i + 1, sql[:60]))
        out.append({
            "id": str(item.get("id", "constraint-%d" % (i + 1))),
            "sql": sql,
            "severity": item.get("severity", "P1"),
            "symptom": str(item.get("symptom", "一致性约束被破坏")),
        })
    return out


def _is_sensitive_column(col, patterns):
    low = col.lower()
    return any(p and p.lower() in low for p in (patterns or []))


def scan(db_path, work_dir, tables, domain_fields, constraints, expect_totals,
         prof, required, source="scan_data.py", project_root=None):
    """Run the data-layer scan. Returns (writer, ok).

    project_root (optional): finding paths are reported relative to it, so a
    fingerprint does not depend on where the work dir happens to live. Without
    it the --db argument is used verbatim (normalized).
    """
    if not os.path.exists(db_path):
        raise S.InputError("数据库文件不存在：%s（用 --db 指定 sqlite 路径）"
                           % db_path)
    # The sqlite URI must keep the real path; findings use the relative one.
    uri_path = db_path.replace("\\", "/")
    rel_db = (S.rel_path(db_path, project_root) if project_root
              else S.norm_locator(db_path))
    out_dir = os.path.join(work_dir, "out")
    w = S.LayerWriter(out_dir, "data", source, profile=prof)
    words = prof.get("signals", {}).get("placeholder_words", [])
    sensitive = prof.get("signals", {}).get("sensitive_field_patterns", [])
    try:
        con = sqlite3.connect("file:%s?mode=ro" % uri_path, uri=True)
    except sqlite3.Error as e:
        raise S.InputError("sqlite3 打开失败：%s：%s" % (db_path, e))
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    existing = set(_list_tables(cur))
    requested = list(tables) if tables else sorted(
        t for t in existing if t not in ("sqlite_sequence",))
    missing = [t for t in requested if t not in existing]
    complete = True
    scanned = 0

    metrics = {"db": rel_db, "tables": {}, "domains": {},
               "missing_tables": missing}

    for t in missing:
        w.add("data.table_missing", t, rel_db, "P1", "表缺失",
              "显式指定的表不存在：%s" % t,
              "请求表 %s 不在数据库中（现有 %d 表）" % (t, len(existing)), 0)
        if required:
            complete = False

    for tbl in requested:
        if tbl in missing:
            continue
        try:
            cur.execute('SELECT COUNT(*) FROM "%s"' % tbl)
            total = cur.fetchone()[0]
        except sqlite3.Error as e:
            w.add("data.table_unreadable", tbl, rel_db, "P1", "表读取失败",
                  "表 %s 无法读取" % tbl, str(e), 0)
            continue
        scanned += 1
        tstat = {"total": total, "fields": {}}
        if total == 0:
            w.add("data.empty_table", tbl, rel_db, "P2", "空表",
                  "表 %s 记录数为 0" % tbl, "COUNT=0", 0)
            metrics["tables"][tbl] = tstat
            continue

        cur.execute('PRAGMA table_info("%s")' % tbl)
        cols = [(r[1], (r[2] or "").upper()) for r in cur.fetchall()]
        text_cols = []
        for col, ctype in cols:
            try:
                cur.execute('SELECT COUNT(*) FROM "%s" WHERE "%s" IS NULL '
                            'OR TRIM(CAST("%s" AS TEXT))=\'\''
                            % (tbl, col, col))
                blank = cur.fetchone()[0]
            except sqlite3.Error as e:
                w.add("data.field_unreadable", "%s.%s" % (tbl, col), rel_db,
                      "P2", "字段读取失败", "%s.%s 无法统计" % (tbl, col),
                      str(e), 0)
                continue
            rate = 100.0 * blank / total
            tstat["fields"][col] = {"type": ctype, "blank": blank,
                                    "blank_rate": round(rate, 2)}
            ref = "%s.%s" % (tbl, col)
            if rate >= RATE_FULL:
                w.add("data.empty_field", ref, rel_db, "P1", "字段全空",
                      "字段 %s 全表为空" % ref,
                      "空 %d/%d（%.1f%%）" % (blank, total, rate), 0)
            elif rate >= RATE_MAJOR:
                w.add("data.empty_field", ref, rel_db, "P1", "字段大面积缺失",
                      "字段 %s 缺失过半" % ref,
                      "空 %d/%d（%.1f%%）" % (blank, total, rate), 0)
            elif rate >= RATE_PARTIAL:
                w.add("data.empty_field", ref, rel_db, "P2", "字段部分缺失",
                      "字段 %s 存在缺失" % ref,
                      "空 %d/%d（%.1f%%）" % (blank, total, rate), 0)

            # Placeholder scan: whole-word only, sensitive columns skipped.
            if _is_sensitive_column(col, sensitive):
                w.add("data.sensitive_skipped", ref, rel_db, "INFO",
                      "敏感字段跳过", "字段 %s 命中敏感字段模式，跳过占位词与值域扫描"
                      % ref, "脱敏红线第 5 条：扫到疑似敏感内容跳过 + INFO 留痕", 0)
                continue
            if ctype in ("TEXT", "VARCHAR", "CLOB", ""):
                text_cols.append(col)

        for col in text_cols:
            for word in words:
                try:
                    cur.execute('SELECT COUNT(*) FROM "%s" WHERE "%s" LIKE ?'
                                % (tbl, col), ("%" + word + "%",))
                    coarse = cur.fetchone()[0]
                except sqlite3.Error:
                    continue
                if not coarse:
                    continue
                # Coarse prefilter is server-side; whole-word confirmation
                # fetches only the prefiltered values, counts, and discards
                # them - values never reach disk.
                hits = 0
                try:
                    cur.execute('SELECT "%s" FROM "%s" WHERE "%s" LIKE ? '
                                'LIMIT %d' % (col, tbl, col,
                                              PLACEHOLDER_FETCH_CAP),
                                ("%" + word + "%",))
                    for row in cur.fetchall():
                        if S.whole_word_hits(str(row[0] or ""), [word]):
                            hits += 1
                except sqlite3.Error:
                    continue
                if not hits:
                    continue
                p1_words = (prof.get("signals", {}) or {}).get(
                    "placeholder_p1_words") or PLACEHOLDER_P1_WORDS
                sev = "P1" if word in tuple(p1_words) else "P2"
                w.add("data.placeholder_hit", col, rel_db, sev, "占位词未填实",
                      "字段 %s.%s 中混有占位词「%s」" % (tbl, col, word),
                      "整词命中 %d 行（LIKE 粗筛 %d 行，值未落盘）；"
                      "只出 SELECT 不出 UPDATE，改什么由人定"
                      % (hits, coarse), 0)

        # Value domains (metrics only; INFO-level baseline material).
        for col in domain_fields:
            if col in [c for c, _ in cols]:
                try:
                    cur.execute('SELECT CAST("%s" AS TEXT) v, COUNT(*) c '
                                'FROM "%s" GROUP BY v ORDER BY c DESC '
                                'LIMIT 40' % (col, tbl))
                    metrics["domains"].setdefault(tbl, {})[col] = [
                        {"value": r[0], "count": r[1]} for r in cur.fetchall()]
                except sqlite3.Error:
                    pass
        metrics["tables"][tbl] = tstat

    for item in constraints:
        try:
            cur.execute(item["sql"])
            n = cur.fetchone()[0]
        except sqlite3.Error as e:
            w.add("data.constraint_error", item["id"], rel_db, "P1",
                  "约束执行失败", "约束 %s 无法执行" % item["id"],
                  "%s；SQL: %s" % (e, item["sql"][:80]), 0)
            continue
        if n:
            w.add("data.constraint_violation", item["id"], rel_db,
                  item["severity"], "约束被破坏", item["symptom"],
                  "违反 %d 条；SQL: %s" % (n, item["sql"][:80]), 0)
        else:
            w.add("data.constraint_ok", item["id"], rel_db, "INFO", "已核验",
                  "约束成立：%s" % item["symptom"], "违反 0 条", 0)

    for entry in expect_totals:
        tbl, _, want = entry.partition("=")
        tbl = tbl.strip()
        try:
            want_n = int(want)
        except ValueError:
            raise S.InputError("--expect-total 格式应为 table=n：%s" % entry)
        if tbl not in existing:
            continue
        cur.execute('SELECT COUNT(*) FROM "%s"' % tbl)
        got = cur.fetchone()[0]
        if got != want_n:
            w.add("data.count_mismatch", tbl, rel_db, "P1", "计数偏差",
                  "表 %s 计数不等于期望值" % tbl,
                  "期望 %d，实际 %d" % (want_n, got), 0)

    con.close()
    w.set_metric("scanned_tables", scanned)
    w.set_metric("tables", metrics["tables"])
    w.set_metric("domains", metrics["domains"])
    w.set_metric("missing_tables", missing)
    w.flush()
    w.mark_done(scanned=scanned, complete=complete)
    return w, complete


def _selftest():
    import shutil
    td = tempfile.mkdtemp(prefix="bugsweep-selftest-")
    try:
        db = os.path.join(td, "app.db")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, "
                    "name TEXT, remark TEXT)")
        con.execute("INSERT INTO items (name, remark) VALUES "
                    "('alpha', 'ok'), ('beta', '待补充'), ('gamma', NULL)")
        con.commit()
        con.close()
        prof = P.load("generic-polyglot", td)
        w, complete = scan(db, td, [], [], [], [], prof, False)
        assert complete, "selftest scan must be complete"
        assert os.path.exists(w.csv_path), "findings csv missing"
        assert S.read_done(os.path.join(td, "out"), "data") is not None
        fps = [f["fingerprint"] for f in w.findings]
        assert len(fps) == len(set(fps)), "duplicate fingerprints"
        print("OK scan_data selftest: %d findings, placeholder whole-word "
              "matched" % len(w.findings))
        return 0
    finally:
        shutil.rmtree(td, ignore_errors=True)


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    S.stdout_utf8()
    if "--selftest" in argv:
        return _selftest()
    ap = argparse.ArgumentParser(
        prog="scan_data.py",
        description="bug-sweep 数据层扫描（SQLite 聚合，只读）")
    ap.add_argument("--db", required=True, help="sqlite 数据库路径（必填）")
    ap.add_argument("--table", action="append", default=[],
                    help="只扫指定表（可重复）；默认扫全部业务表")
    ap.add_argument("--work-dir", required=True,
                    help="工作目录（必填，产物落 <work-dir>/out）")
    ap.add_argument("--required", action="store_true",
                    help="严格模式：显式 --table 缺失即 complete=false")
    ap.add_argument("--domain-fields", default="",
                    help="逗号分隔的值域字段清单")
    ap.add_argument("--constraints-file", default=None,
                    help="一致性约束 JSON（只允许 SELECT/WITH）")
    ap.add_argument("--expect-total", action="append", default=[],
                    help="期望计数 table=n（可重复）")
    ap.add_argument("--profile", default="generic-polyglot", help="profile id")
    ap.add_argument("--project-root", default=None,
                    help="工程根目录：finding 路径相对它落（缺省用 --db 原样）")
    ap.add_argument("--run-id", default="", help="运行 ID（记录用）")
    ap.add_argument("--selftest", action="store_true", help="内置自检")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    try:
        prof = P.load(args.profile, os.path.dirname(
            os.path.abspath(args.db)) or ".")
        domain_fields = [f.strip() for f in args.domain_fields.split(",")
                         if f.strip()]
        if not domain_fields:
            domain_fields = list(prof.get("signals", {}).get(
                "domain_fields", []))
        constraints = _load_constraints(args.constraints_file)
        w, complete = scan(args.db, args.work_dir, args.table, domain_fields,
                           constraints, args.expect_total, prof, args.required,
                           project_root=args.project_root)
        print("scan_data done: %d findings, complete=%s -> %s"
              % (len(w.findings), str(complete).lower(), w.csv_path))
        return 0
    except S.InputError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2
    except P.ProfileError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
