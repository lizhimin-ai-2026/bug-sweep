# Per-layer scanning criteria (five layers + four deep kinds)

> Signal names, anchors and severity policies are NOT re-listed here: the
> single source of truth is references/signal-contract.md. This file is the
> criteria narrative: what each layer sweeps, what makes a hit, and which
> false-positive class guards it.

## Data layer (scan_data.py, deterministic)

Aggregate-only SQLite scanning, read-only: null rates per column, whole-word
placeholder hits in TEXT values, declarative consistency constraints (SELECT
/ WITH only), expected counts. Guard rails: sensitive columns (profile
patterns) skip the value-domain scan and leave an INFO; placeholder evidence
says "matched N rows" without persisting any value; a missing explicitly
requested table is P1 and sets complete=false (never a silent skip).
Null-rate grades: >=99.5% all-null P1, >=50% P1, >=20% P2 - thresholds, not
verdicts (class 11).

## API layer (scan_api.py, deterministic)

HTTP status and JSON structure only. Preserved mechanisms, none droppable:
rate limiting (default 1.2 req/s), exponential backoff (1s/2s/4s), failures
and 404 in separate buckets, and the completeness assertion
success + 404 + failed == range length - failing it forces P1
"scan incomplete" and complete=false. Not-found semantics probe, id gaps,
field null rates while walking ids, expected totals and contracted fields.
No default base URL may exist in code (class 1 of the purification list);
`--base` is required.

## Runtime layer (scan_deploy.py --layers runtime, mixed)

Local source vs live deployment snapshot: ghost functions (deployed, no
source) P1, undeployed P2, config drift P2 with the class-8 derivation,
env reconciliation in two tiers (key-class P1 / fallback-class P2), dual
config-channel mismatch, hardcoded secret-like literals - evidence carries
offset + length + type ONLY, never a value fragment (redaction line 1),
write-guard bypass switches, un-awaited async candidates. A missing snapshot
exits 2: degrading to "local only" would silently drop ghost functions.

## Schedule layer (scan_deploy.py --layers schedule, deterministic)

Three-way reconciliation: local declaration / live snapshot / function body.
Cloud-only trigger P1; local-only P2 upward (check logs first - class 4);
a timer branch in a function body with no trigger on either side P1, unless
the entry takes an event parameter. Cron field count follows the profile
(7 for the WeChat/SCF family, 5 elsewhere). Log-evidence values come from
the profile; the snapshot records trigger names, never payloads.

## Client layer (scan_code.py, mixed)

Page inventory (standard entry files per profile), route alignment
(dangling P1 / unregistered INFO; a corrupt manifest is P0 with
complete=false), exported-function dead code with the module-internal-call
rule (a name seen twice in its own file is definition + internal call; the
export table itself is wiring, not a call - otherwise nothing is ever dead),
backup hygiene against every ignore-rule location, whole-word placeholder
residue (INFO) and leftover TODO/FIXME markers (P2), paired share-capability
matrix (asymmetric pages only, INFO - class 7). Ownership rules map
cloudfunctions/** to runtime so the two layers never double-report.

## Deep kind 1 - dead code (deterministic)

Reachability from entries over one import graph. Unreachable function P2;
the same name appearing in any string literal downgrades to INFO (dynamic
reference). Test files are exempt: frameworks call them, nothing imports
them. Entry modules: conventional names, __main__ guards, package main.

## Deep kind 2 - dependency cycles (deterministic)

Strongly connected components of the module-level import graph. A 2-node
direct cycle is P1; more nodes P2; a cycle that exists only through
function-level lazy imports is P2 "mitigated". The anchor is the smallest
node first along the edge direction with the first node repeated; the path
is the file holding the closing edge. Only module existence is reported,
never "the dependency is wrong" - that is a human judgment.

## Deep kind 3 - complexity (heuristic + calibration)

Lines, nesting depth, McCabe, duplicate blocks. Thresholds are solved, not
hardcoded: n<30 uses the absolute floor; otherwise max(floor, P95); every
finding carries value + threshold + source so it can be recomputed.
Long/nested functions are risk hints ("suggest splitting"), never
"must fix". Duplicate blocks exclude templates and prompt word tables
(class 3) and compare normalized skeletons, not raw text.

## Deep kind 4 - silent zones (heuristic, candidates only)

Empty catch / except pass: uncommented P2 candidate, an explanatory comment
inside the block downgrades to INFO. Fallback passthrough (missing key
returned as-is), Go err discard (`_, _ = f()` / `x, _ := f()`) and bare
recover(). The script emits position + context only; it never grades.
Verification asks "did the effect appear", never "did it error" - these bugs
hide behind clean logs. See references/silent-failures.md.
