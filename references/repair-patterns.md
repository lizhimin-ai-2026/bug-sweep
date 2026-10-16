# Repair patterns, iron rules, proposal buffer and undo

## Four paradigms (distilled from real repair sessions; project identity removed)

| Paradigm | Fits | One-line signature |
| --- | --- | --- |
| 1. Command-style | one AI, verify as you go | one instruction at a time; next one only after verification passes |
| 2. Staged-script | server / database high-risk | stage0 backup probe -> stage-by-stage edits -> a rollback point per stage |
| 3. Freeze-order | several AIs on one environment | stop writes first, publish the forbidden list, correct attribution with measured evidence |
| 4. Review-decide-seal | pre-release / competition freeze | review admits fault before deciding; only the named scope moves; single exit |

## Repair iron rules (same force as the scan iron rules)

1. Back up before touching - every stage opens with a rollback point;
   rolling back beats "push through".
2. Only fill empties, never overwrite - data repair takes the
   COALESCE(NULLIF(col,''), new) shape; existing values are never touched;
   "what this batch does not move" is listed explicitly.
3. Minimal change, single duty, every line explainable - if more code must
   move than the instruction named, stop and report. No drive-by edits.
4. Never fill in secrets on the user's behalf - stop and ask the owner;
   do not invent, do not leave blank.
5. Stop the moment verification fails - walk the re-verification list; any
   failure returns the full output without self-"fixing".

## Proposal buffer (mandatory before any architecture change)

Deep optimization is a large, risky move, so the buffer is forced:

```
deep scan results
  -> evidence aggregation (ledger.py --view proposal)
  -> the model writes three suggestions, each with what-changes / blast
     radius / risk / rollback difficulty, ranked by gain-over-risk
  -> the user picks one of the three, or "other"
  -> only the picked one becomes a concrete change plan
  -> change -> verify -> undo fallback
```

Ranking gradient: low-risk quick wins (dead code, duplicate blocks, silent
zones) -> medium-risk refactors (split long functions, decouple modules) ->
high-risk architecture moves (layer reordering, data-flow rework). The user's
pick defines the execution boundary; the model proposes, it never chooses.
"Other" keeps full freedom: describe an idea, report only, "send me the whole
report first", or contest the ranking and demand a rewrite.

## Undo semantics (self-managed, copy not move)

The undo.py backup command copies (never moves - Windows locks and
half-moved trees break move semantics) into <work-dir>/undo/<id>/mirror/
with a manifest (rel / existed / action / sha256_before / bytes / mtime /
mode). Files that do not exist yet are recorded as to-be-created, so
restore DELETES them - deletion only ever comes from a manifest record,
never from inference. Restore overwrites back per item, re-computes sha256,
and reports honestly: any mismatch is a per-item failure with a non-zero
exit, never "all restored". A restored snapshot refuses a second restore
(exit 2) unless --force. Retention keeps the newest three snapshots and
only ever deletes directories carrying a tool-written manifest.

## Verification priority

Independent-path readback first (another entry point, another tool), then
the user-visible effect ("did it appear"), then logs, then self-tests. A
script's own pass is evidence of nothing.
