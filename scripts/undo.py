#!/usr/bin/env python3
"""undo - self-managed backup / rollback for bug-sweep repair sessions.

Copy semantics, not move: a move-based rollback does not fit code edits
(Windows file locks on open sources, half-moved trees, and backups that
were cleaned up before the rollback all break it).

  backup   copy the listed files into <work-dir>/undo/<id>/mirror/ and
           record a manifest (sha256, bytes, mtime, mode). Files that do
           not exist yet are recorded as existed:false so a later restore
           DELETES them - deletion only ever comes from a manifest record,
           never from inference.
  list     enumerate snapshots under <work-dir>/undo/.
  restore  overwrite-write existed:true items back (verified against
           sha256_before), delete existed:false items, verify every item,
           report honestly: any mismatch -> non-zero exit + "partial".
           Re-entry protection: a restored snapshot refuses a second
           restore (exit 2) unless --force.
  verify   read-only integrity check against the manifest.

Retention keeps the newest 3 snapshots and only ever deletes directories
that carry a manifest written by this tool.

Usage:
    python undo.py backup  --root <D> --paths <p1,p2,...> --work-dir <W>
    python undo.py list    --work-dir <W>
    python undo.py restore --snapshot <W>/undo/<id> [--force]
    python undo.py verify  --snapshot <W>/undo/<id>

Exit codes: 0 success / 1 partial or verification failure /
2 usage or input error.
Standard library only; importing this module has no side effects.
"""
import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import time

TOOL_VERSION = "2.0.0"
RETENTION = 3


class UndoError(Exception):
    """Usage / input error -> exit 2."""


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot_dir(work_dir, snap):
    """Accept a snapshot dir path or a bare snapshot id."""
    if os.path.isdir(snap) and os.path.exists(
            os.path.join(snap, "manifest.json")):
        return os.path.abspath(snap)
    cand = os.path.join(work_dir, "undo", snap)
    if os.path.exists(os.path.join(cand, "manifest.json")):
        return cand
    raise UndoError("快照不存在或不是本工具的快照：%s（查找 %s）"
                    % (snap, cand))


def _load_manifest(snap_dir):
    path = os.path.join(snap_dir, "manifest.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), path
    except (OSError, json.JSONDecodeError) as e:
        raise UndoError("manifest 不可读：%s：%s" % (path, e))


def _save_manifest(manifest, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)


def _safe_rel(root, rel):
    """Reject absolute paths and escapes: rollback must stay inside root."""
    rel = rel.strip()
    if not rel:
        raise UndoError("空路径")
    # Windows isabs() misses POSIX-style "/etc/passwd"; a leading separator
    # of either flavour is always meant as absolute - refuse it explicitly.
    if rel[:1] in ("/", "\\") or os.path.isabs(rel) or rel.startswith("~"):
        raise UndoError("拒绝绝对路径：%s（只接受 root 内的相对路径）" % rel)
    rel = rel.strip("/\\")
    if not rel:
        raise UndoError("空路径")
    parts = []
    for seg in rel.replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            raise UndoError("拒绝越界路径（含 ..）：%s" % rel)
        parts.append(seg)
    return "/".join(parts)


# ------------------------------------------------------------------ commands --

def cmd_backup(args):
    root = os.path.abspath(args.root)
    work_dir = os.path.abspath(args.work_dir)
    if not os.path.isdir(root):
        raise UndoError("root 不存在：%s" % root)
    rels = [_safe_rel(root, p) for p in args.paths.split(",") if p.strip()]
    if not rels:
        raise UndoError("--paths 不能为空")
    now = time.localtime()
    snap_id = time.strftime("%Y%m%d-%H%M%S", now)
    snap_dir = os.path.join(work_dir, "undo", snap_id)
    if os.path.exists(snap_dir):     # same-second collision: suffix it
        snap_id = "%s-%d" % (snap_id, int(time.time() % 1000))
        snap_dir = os.path.join(work_dir, "undo", snap_id)
    mirror = os.path.join(snap_dir, "mirror")
    os.makedirs(mirror, exist_ok=True)

    items = []
    for rel in rels:
        src = os.path.join(root, rel)
        item = {"rel": rel}
        if os.path.isfile(src):
            dst = os.path.join(mirror, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)      # copy, never move
            st = os.stat(src)
            item.update({
                "existed": True, "action": "copy",
                "sha256_before": _sha256_file(src),
                "bytes": st.st_size, "mtime": int(st.st_mtime),
                "mode": stat.filemode(st.st_mode),
            })
        elif os.path.isdir(src):
            raise UndoError("%s 是目录：备份只支持文件，请展开为文件清单" % rel)
        else:
            item.update({"existed": False, "action": "create",
                         "sha256_before": None, "bytes": 0})
        items.append(item)

    manifest = {
        "snapshot_id": snap_id,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", now),
        "root": root,
        "tool_version": TOOL_VERSION,
        "retention": RETENTION,
        "items": items,
    }
    _save_manifest(manifest, os.path.join(snap_dir, "manifest.json"))
    _apply_retention(work_dir)
    existed = sum(1 for i in items if i["existed"])
    print("backup: snapshot %s at %s" % (snap_id, snap_dir))
    print("  %d item(s): %d copied, %d recorded as to-be-created"
          % (len(items), existed, len(items) - existed))
    return 0


def _apply_retention(work_dir):
    """Keep the newest RETENTION snapshots; delete only tool-owned dirs."""
    undo_dir = os.path.join(work_dir, "undo")
    if not os.path.isdir(undo_dir):
        return
    snaps = []
    for name in os.listdir(undo_dir):
        d = os.path.join(undo_dir, name)
        if os.path.exists(os.path.join(d, "manifest.json")):
            snaps.append((name, d))
    snaps.sort(reverse=True)          # snapshot ids are time-formatted
    for name, d in snaps[RETENTION:]:
        shutil.rmtree(d, ignore_errors=True)
        print("  retention: removed old snapshot %s" % name)


def cmd_list(args):
    undo_dir = os.path.join(os.path.abspath(args.work_dir), "undo")
    if not os.path.isdir(undo_dir):
        print("（无 undo 目录：%s）" % undo_dir)
        return 0
    found = False
    for name in sorted(os.listdir(undo_dir), reverse=True):
        d = os.path.join(undo_dir, name)
        mpath = os.path.join(d, "manifest.json")
        if not os.path.exists(mpath):
            continue
        found = True
        try:
            with open(mpath, "r", encoding="utf-8") as f:
                m = json.load(f)
        except (OSError, json.JSONDecodeError):
            print("- %s（manifest 不可读）" % name)
            continue
        print("- %s｜%s｜root=%s｜%d 项｜%s"
              % (name, m.get("created_at", "?"), m.get("root", "?"),
                 len(m.get("items", [])),
                 ("已恢复于 %s" % m["restored_at"]) if m.get("restored_at")
                 else "未恢复"))
    if not found:
        print("（undo 目录下没有本工具的快照）")
    return 0


def cmd_restore(args):
    work_dir = os.path.abspath(args.work_dir)
    snap_dir = _snapshot_dir(work_dir, args.snapshot)
    manifest, mpath = _load_manifest(snap_dir)
    if manifest.get("restored_at") and not args.force:
        sys.stderr.write(
            "error: 快照 %s 已于 %s 恢复过（幂等重入保护）。"
            "确认要再恢复一次用 --force。\n"
            % (manifest.get("snapshot_id"), manifest["restored_at"]))
        return 2
    root = manifest.get("root", "")
    if not os.path.isdir(root):
        raise UndoError("manifest 记录的 root 不存在：%s" % root)
    mirror = os.path.join(snap_dir, "mirror")

    results = []
    failures = 0
    for item in manifest.get("items", []):
        rel = item["rel"]
        target = os.path.join(root, rel)
        if item.get("existed"):
            src = os.path.join(mirror, rel)
            if not os.path.isfile(src):
                results.append((rel, "mirror-missing",
                                "备份副本缺失：%s" % src))
                failures += 1
                continue
            os.makedirs(os.path.dirname(target) or root, exist_ok=True)
            shutil.copy2(src, target)      # overwrite-write back
            got = _sha256_file(target)
            if got == item.get("sha256_before"):
                results.append((rel, "restored", "sha256 校验一致"))
            else:
                results.append((rel, "mismatch",
                                "恢复后 sha256 与 manifest 不符"))
                failures += 1
        else:
            if os.path.exists(target):
                try:
                    os.remove(target)
                    results.append((rel, "deleted",
                                    "manifest 登记的新建文件，已删除"))
                except OSError as e:
                    results.append((rel, "delete-failed", str(e)))
                    failures += 1
            else:
                results.append((rel, "absent",
                                "登记的新建文件本就不存在，无需处理"))

    for rel, status, detail in results:
        print("  [%s] %s — %s" % (status, rel, detail))
    if failures:
        print("restore: 部分恢复完成（%d/%d 项失败）。未写 restored_at，"
              "可修复后重试；禁止当作全部恢复成功。"
              % (failures, len(manifest.get("items", []))))
        return 1
    manifest["restored_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z",
                                            time.localtime())
    _save_manifest(manifest, mpath)
    print("restore: %d 项全部恢复并逐项校验通过（快照 %s）"
          % (len(manifest.get("items", [])), manifest.get("snapshot_id")))
    return 0


def cmd_verify(args):
    work_dir = os.path.abspath(args.work_dir)
    snap_dir = _snapshot_dir(work_dir, args.snapshot)
    manifest, _mpath = _load_manifest(snap_dir)
    root = manifest.get("root", "")
    problems = 0
    for item in manifest.get("items", []):
        rel = item["rel"]
        target = os.path.join(root, rel)
        if item.get("existed"):
            if not os.path.isfile(target):
                print("  [missing] %s — 文件不存在" % rel)
                problems += 1
                continue
            got = _sha256_file(target)
            if got == item.get("sha256_before"):
                print("  [unchanged] %s — 与备份时一致" % rel)
            else:
                print("  [modified] %s — 与 sha256_before 不符（被改过）"
                      % rel)
                problems += 1
        else:
            if os.path.exists(target):
                print("  [appeared] %s — 备份时不存在，现在存在（新建文件）"
                      % rel)
                problems += 1
            else:
                print("  [absent] %s — 与备份时一致（不存在）" % rel)
    print("verify: %d 项，%d 处与快照状态不符"
          % (len(manifest.get("items", [])), problems))
    return 0 if problems == 0 else 1


# --------------------------------------------------------------------- CLI --

def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    ap = argparse.ArgumentParser(
        prog="undo.py",
        description="bug-sweep 自管备份 / 回滚（copy 语义 + 逐项校验）")
    ap.add_argument("command", choices=["backup", "list", "restore", "verify"])
    ap.add_argument("--root", default=None, help="项目根目录（backup 用）")
    ap.add_argument("--paths", default=None,
                    help="逗号分隔的相对路径清单（backup 用）")
    ap.add_argument("--work-dir", required=True, help="工作目录（必填）")
    ap.add_argument("--snapshot", default=None,
                    help="快照目录或快照 id（restore / verify 用）")
    ap.add_argument("--force", action="store_true",
                    help="允许对已恢复的快照再次 restore")
    args = ap.parse_args(argv)

    try:
        if args.command == "backup":
            if not args.root or not args.paths:
                raise UndoError("backup 需要 --root 与 --paths")
            return cmd_backup(args)
        if args.command == "list":
            return cmd_list(args)
        if not args.snapshot:
            raise UndoError("%s 需要 --snapshot <dir|id>" % args.command)
        if args.command == "restore":
            return cmd_restore(args)
        return cmd_verify(args)
    except UndoError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2
    except OSError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
