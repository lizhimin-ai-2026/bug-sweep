#!/usr/bin/env python3
"""scan_api - API contract layer scanner.

HTTP contract checks with the safety mechanisms intact: rate limiting
(<=1.5 req/s), exponential backoff retries (1s/2s/4s), failure and 404 kept
in separate buckets, and the completeness assertion
(success + 404 + failure == range length) which fails the whole layer when
rate limiting silently eats part of the range.

Usage:
    python scan_api.py --base <url> [--paths-file <json>] [--expect-total n]
                       [--id-range 1-280] [--not-found-probe <path>]
                       [--rate 1.2] [--work-dir D] [--profile P]

Outputs (under <work-dir>/out, overwrite mode):
    findings_api.csv | metrics_api.json | _done_api.txt

Exit codes: 0 complete / 2 input error or base unreachable.
Standard library only; importing this module has no side effects.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweeplib as S  # noqa: E402
import profile as P  # noqa: E402

DEFAULT_RATE = 1.2
SAFE_RATE = 1.5
RETRY_BACKOFF = (1.0, 2.0, 4.0)
HTTP_TIMEOUT = 10.0
MAX_BODY_BYTES = 4 * 1024 * 1024

# Keys under which a JSON list payload may hide (checked in this order).
LIST_KEYS = ("items", "data", "list", "results", "records")


class RateLimiter(object):
    """Minimum interval between requests; deterministic, no threads."""

    def __init__(self, rate):
        self.interval = 1.0 / float(rate) if rate and rate > 0 else 0.0
        self._last = [0.0]

    def wait(self):
        if self.interval <= 0:
            return
        now = time.monotonic()
        delta = now - self._last[0]
        if delta < self.interval:
            time.sleep(self.interval - delta)
        self._last[0] = time.monotonic()


def http_get(url, limiter, retries=len(RETRY_BACKOFF)):
    """GET with backoff. Returns (status, body_text, error).

    404 is a definitive answer (its own bucket); transport failures retry
    with 1s/2s/4s backoff and stay in the failure bucket.
    """
    last_err = ""
    for attempt in range(retries + 1):
        limiter.wait()
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "bug-sweep/2.0 contract-scan",
                              "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                body = resp.read(MAX_BODY_BYTES).decode("utf-8", "replace")
                return resp.status, body, ""
        except urllib.error.HTTPError as e:
            try:
                body = e.read(MAX_BODY_BYTES).decode("utf-8", "replace")
            except Exception:
                body = ""
            return e.code, body, ""
        except Exception as e:  # URLError, timeout, reset ...
            last_err = "%s: %s" % (type(e).__name__, e)
            if attempt < retries:
                time.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
    return 0, "", last_err


def _extract_list(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in LIST_KEYS:
            v = payload.get(key)
            if isinstance(v, list):
                return v
    return []


def _segment_analysis(ids):
    """Failed ids as text: contiguous segments (rate-limit signature) vs
    scattered points (network jitter). Evidence only; deterministic."""
    if not ids:
        return ""
    ids = sorted(ids)
    segments, start, prev = [], ids[0], ids[0]
    for i in ids[1:]:
        if i == prev + 1:
            prev = i
            continue
        segments.append((start, prev))
        start = prev = i
    segments.append((start, prev))
    if all(a == b for a, b in segments):
        return "散点失败 %s（网络抖动特征：失败编号互不相邻）" % ", ".join(
            str(i) for i in ids)
    return "成段失败 %s（限流特征：失败编号连续出现）" % ", ".join(
        "%d-%d" % (a, b) if a != b else "%d" % a for a, b in segments)


def _load_paths_file(path):
    if not path:
        return []
    if not os.path.exists(path):
        raise S.InputError("paths-file 不存在：%s" % path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise S.InputError("%s: JSON 解析失败（第 %d 行）：%s"
                           % (path, e.lineno, e.msg))
    items = data.get("paths", data) if isinstance(data, dict) else data
    out = []
    for i, item in enumerate(items):
        if not item.get("path"):
            raise S.InputError("%s: 第 %d 条缺少 path" % (path, i + 1))
        out.append(item)
    return out


def scan(base, work_dir, paths, expect_total, id_range, not_found_probe,
         rate, prof, source="scan_api.py"):
    base = base.rstrip("/")
    limiter = RateLimiter(rate)
    out_dir = os.path.join(work_dir, "out")
    w = S.LayerWriter(out_dir, "api", source, profile=prof)
    sensitive = prof.get("signals", {}).get("sensitive_field_patterns", [])
    scanned = 0
    complete = True
    metrics = {"base": base, "rate": rate, "paths": []}

    # --- 0. base reachability: unreachable base aborts the layer (exit 2) ---
    status, _, err = http_get(base + "/", limiter)
    if status == 0:
        raise S.InputError("base 不可达：%s（%s）。修法：确认 URL、网络与鉴权后重跑"
                           % (base, err))

    # --- 1. declared paths ---
    for item in paths:
        p = item["path"]
        url = base + (p if p.startswith("/") else "/" + p)
        status, body, err = http_get(url, limiter)
        scanned += 1
        rec = {"path": p, "status": status}
        if status != 200:
            w.add("api.path_error", p, url, "P2", "路径请求失败",
                  "路径 %s 未返回 200" % p,
                  "status=%s err=%s（重试 %d 次后仍失败，与 404 分桶）"
                  % (status or "无响应", err or "-", len(RETRY_BACKOFF)), 0)
            metrics["paths"].append(rec)
            continue
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as e:
            w.add("api.bad_json", p, url, "P2", "响应不可解析",
                  "路径 %s 返回非 JSON" % p, str(e), 0)
            metrics["paths"].append(rec)
            continue
        rows = _extract_list(payload)
        if not rows and not isinstance(payload, (list, dict)):
            rows = []
        rec["rows"] = len(rows)
        if item.get("expect_total") is not None and isinstance(payload, dict):
            got = payload.get("total")
            if got is not None and int(got) != int(item["expect_total"]):
                w.add("api.total_mismatch", p, url, "P1", "总数不符",
                      "路径 %s 的 total 不等于期望值" % p,
                      "期望 %s，实际 %s" % (item["expect_total"], got), 0)
        for field in item.get("expect_fields", []):
            # Check a list payload (rows) AND a single detail object payload.
            targets = rows
            if not targets and isinstance(payload, dict):
                targets = [payload]
            missing = any(isinstance(t, dict) and field not in t
                          for t in targets)
            if missing:
                scope = "首行" if rows else "对象"
                w.add("api.field_missing", "%s.%s" % (p, field), url, "P2",
                      "契约字段缺失",
                      "路径 %s 响应缺少字段 %s" % (p, field),
                      "字段名级证据（不记值）：%s无 %s" % (scope, field), 0)
        metrics["paths"].append(rec)

    # --- 2. expect-total on the bare base (legacy single-endpoint form) ---
    if expect_total is not None and not paths:
        status, body, err = http_get(base + "/", limiter)
        if status == 200:
            try:
                payload = json.loads(body)
                got = payload.get("total") if isinstance(payload, dict) else None
                if got is not None and int(got) != int(expect_total):
                    w.add("api.total_mismatch", "/", base, "P1", "总数不符",
                          "base 的 total 不等于期望值",
                          "期望 %s，实际 %s" % (expect_total, got), 0)
            except (json.JSONDecodeError, AttributeError, ValueError):
                pass

    # --- 3. not-found semantics probe ---
    if not_found_probe:
        url = base + (not_found_probe if not_found_probe.startswith("/")
                      else "/" + not_found_probe)
        status, _, _ = http_get(url, limiter)
        scanned += 1
        if status != 404:
            w.add("api.not_found_semantics", not_found_probe, url, "P2",
                  "404 语义缺失", "不存在的资源未返回 404",
                  "探针 %s 返回 status=%s（期望 404）" % (not_found_probe,
                                                        status or "无响应"), 0)

    # --- 4. id-range walk with the two-bucket completeness assertion ---
    if id_range:
        lo, hi = id_range
        template = None
        field_scan = []
        for item in paths:
            if item.get("id_template"):
                template = item["id_template"]
                field_scan = item.get("field_scan", [])
                break
        if template is None:
            template = (paths[0]["path"] if paths else "/items") + "/{id}"
        success = notfound = failed = 0
        failed_ids, gap_ids, empty_hits = [], [], {}
        for i in range(lo, hi + 1):
            url = base + template.replace("{id}", str(i))
            status, body, err = http_get(url, limiter)
            scanned += 1
            if status == 200:
                success += 1
                if field_scan:
                    try:
                        payload = json.loads(body)
                    except json.JSONDecodeError:
                        payload = None
                    row = payload
                    if isinstance(payload, dict):
                        for key in LIST_KEYS + ("item", "detail"):
                            v = payload.get(key)
                            if isinstance(v, dict):
                                row = v
                                break
                            if isinstance(v, list) and v:
                                row = v[0]
                                break
                    if isinstance(row, dict):
                        for field in field_scan:
                            if any(p and p.lower() in field.lower()
                                   for p in sensitive):
                                continue
                            v = row.get(field)
                            if v is None or str(v).strip() == "":
                                empty_hits[field] = empty_hits.get(field, 0) + 1
            elif status == 404:
                notfound += 1
                gap_ids.append(i)
            else:
                failed += 1
                failed_ids.append(i)
        span = hi - lo + 1
        for field, n in sorted(empty_hits.items()):
            w.add("api.field_empty", "%s.%s" % (template, field), template,
                  "P2", "字段空值", "字段 %s 在编号遍历中存在空值" % field,
                  "空值 %d/%d（只记字段名与存在性，不记值）" % (n, success), 0)
        if gap_ids:
            w.add("api.id_gap", "range:%d-%d" % (lo, hi), template, "P2",
                  "编号空洞", "编号遍历发现确定不存在的编号",
                  "404 编号 %d 个：%s（与失败分桶，404=确定不存在）"
                  % (len(gap_ids), _compact(gap_ids)), 0)
        if failed_ids:
            w.add("api.id_walk_failures", "range:%d-%d" % (lo, hi), template,
                  "P2", "遍历失败", "编号遍历存在重试后仍失败的请求",
                  "失败 %d/%d：%s；%s"
                  % (len(failed_ids), span, _compact(failed_ids),
                     _segment_analysis(failed_ids)), 0)
        if success + notfound + failed != span:
            complete = False
            w.add("api.incomplete", "range:%d-%d" % (lo, hi), template, "P1",
                  "扫描不完整", "完整性断言不通过",
                  "成功 %d + 404 %d + 失败 %d != 区间长度 %d；限流或网络不稳，"
                  "本层结论不可信" % (success, notfound, failed, span), 0)
        metrics["id_range"] = {"lo": lo, "hi": hi, "success": success,
                               "not_found": notfound, "failed": failed,
                               "span": span}

    w.set_metric("scanned", scanned)
    w.set_metric("paths", metrics["paths"])
    if "id_range" in metrics:
        w.set_metric("id_range", metrics["id_range"])
    w.flush()
    w.mark_done(scanned=scanned, complete=complete)
    return w, complete


def _compact(ids, limit=20):
    ids = sorted(ids)
    if len(ids) <= limit:
        return ",".join(str(i) for i in ids)
    return "%s ... %s（共 %d 个）" % (ids[0], ids[-1], len(ids))


def _selftest():
    limiter = RateLimiter(1.2)
    t0 = time.monotonic()
    limiter.wait()
    limiter.wait()
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.7, "rate limiter too fast: %.2fs" % elapsed
    assert _segment_analysis([3, 4, 5, 6]) .find("成段") >= 0
    assert _segment_analysis([3, 9, 15]).find("散点") >= 0
    assert _extract_list({"items": [1, 2]}) == [1, 2]
    assert _extract_list({"data": {"a": 1}}) == []
    print("OK scan_api selftest: rate limiter + bucket analysis (no network)")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    S.stdout_utf8()
    if "--selftest" in argv:
        return _selftest()
    ap = argparse.ArgumentParser(
        prog="scan_api.py",
        description="bug-sweep 接口层扫描（HTTP 契约，限速 + 分桶 + 完整性断言）")
    ap.add_argument("--base", required=True,
                    help="接口 base URL（必填，无默认值）")
    ap.add_argument("--paths-file", default=None,
                    help="路径声明 JSON（path/expect_fields/expect_total/"
                         "id_template/id_range/field_scan）")
    ap.add_argument("--expect-total", type=int, default=None,
                    help="base 列表接口期望 total")
    ap.add_argument("--id-range", default=None, help="编号遍历区间，如 1-280")
    ap.add_argument("--not-found-probe", default=None,
                    help="404 语义探针路径")
    ap.add_argument("--rate", type=float, default=DEFAULT_RATE,
                    help="每秒请求数（默认 1.2，安全值 <=1.5）")
    ap.add_argument("--work-dir", required=True,
                    help="工作目录（必填，产物落 <work-dir>/out）")
    ap.add_argument("--profile", default="generic-polyglot", help="profile id")
    ap.add_argument("--run-id", default="", help="运行 ID（记录用）")
    ap.add_argument("--selftest", action="store_true", help="内置自检")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    try:
        prof = P.load(args.profile, ".")
        paths = _load_paths_file(args.paths_file)
        id_range = None
        if args.id_range:
            lo_s, _, hi_s = args.id_range.partition("-")
            try:
                id_range = (int(lo_s), int(hi_s))
            except ValueError:
                raise S.InputError("--id-range 格式应为 a-b：%s" % args.id_range)
        if args.rate > SAFE_RATE:
            sys.stderr.write("warning: rate %.2f 超过安全值 %.1f 次/秒，"
                             "限流误报风险自负\n" % (args.rate, SAFE_RATE))
        w, complete = scan(args.base, args.work_dir, paths, args.expect_total,
                           id_range, args.not_found_probe, args.rate, prof)
        print("scan_api done: %d findings, complete=%s -> %s"
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
