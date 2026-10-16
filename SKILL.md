---
name: bug-sweep
description: Full-spectrum defect sweep of a multi-tier project into a recomputable defect ledger for human triage and layer-by-layer repair; ships four battle-tested repair paradigms and a deep-scan/architecture buffer (dead code, complexity, dependencies, silent zones -> three suggestions plus "other" -> user decides -> undoable). Use when symptoms like "fix one, break another", "still fixing the same bug on day three", "no idea how many traps remain before release", "unsure which link of the data chain broke", or "structure is rotting, deep bugs hide in it, want to optimize the architecture but fear breaking it" appear; also when the user asks for a systematic bug sweep, a tech-debt inventory, a pre-release risk census, normative repair execution, or deep scanning plus architecture optimization; also when one change must be verified consistently across database, API, cloud functions, scheduled tasks and frontend.
description_zh: 全栈卫士的英文开源版：面向任意技术栈的分层缺陷普查与静默失效检测工具。把「改一处坏一处」「修了三天还在重复修」「上线前不知道还有多少坑」这类循环变成一次性的全量清单，产出可复算的缺陷台账交人分诊，再按层批量修复；内置死链/复杂度/依赖环/静默区四类深扫与「建议书-拍板-撤销兜底」缓冲机制。中文用户可改用 bug-sweep-cn（能力完全对齐，仅语言与默认 profile 不同）。
description_en: ALL Bug Sweep turns "fix one, break another" loops into a one-pass, recomputable inventory: five scanning layers (data, API, runtime, schedule, client) plus four deep-scan kinds (dead code, complexity, dependency cycles, silent zones), one fingerprint-based ledger, four repair paradigms, and a mandatory propose-decide-undo buffer before any architecture change. Stdlib-only Python; zero third-party dependencies; profiles carry every platform fact so the scripts stay project-agnostic.
version: 2.0.0
author: laoli
---

# ALL Bug Sweep · Layered Defect Sweep and Silent-Failure Detection

Fix bugs one at a time and the failure mode is always the same: a symptom arrives,
you change one place, a new symptom appears, and three days later you are still
circling the same module. The root cause is not slow fixing - it is that **nobody
knows how many defects exist or which layer each lives in**. This skill inverts
it: **sweep every suspicious point into one ledger first, then repair layer by
layer.** The scan cost is fixed; it converts unbounded unknown into bounded known.

## Trigger conditions

Use it when any of these holds:

- A change must be verified consistently across database, API, cloud functions,
  scheduled tasks and frontend at the same time.
- The user asks for a systematic bug sweep, a tech-debt inventory, a pre-release
  risk census, or "how many traps are left".
- Symptoms appear: "fix one, break another"; "still fixing the same bug on day
  three"; "unsure which link of the data chain broke".
- The codebase's structure itself is suspected (dead code, cyclic dependencies,
  silently swallowed errors) and an architecture optimization is wanted - but
  breaking things is feared.
- Repair must follow a normative, reversible, layer-staged discipline.

Do NOT use it when: the task is a single well-localized edit (a sweep would cost
more than it saves); the target is outside the user's own project (the
redaction red line forbids scanning other people's data); or the project has no
runnable source tree at all (there is nothing to parse).

## Input contract

| Input | Required | Missing it means |
| --- | --- | --- |
| `--project-root` | yes (sweep) | exit 2 - no guessing where the project is |
| `--work-dir` | yes (every script) | exit 2 - products never land in the skill dir |
| `--profile <id\|auto>` | yes (sweep) | exit 2 - auto ties or zero hits also exit 2, never a silent guess |
| `--db` | per layer | data layer skipped with an explicit note |
| `--base` | per layer | API layer skipped (no default domain may be baked in) |
| `--live` | per layer | runtime/schedule skipped - never degrades to "local only" |
| `--root` | per layer | client/runtime layer skipped with an explicit note |

A skipped layer is recorded in the sweep summary with its reason; it is never
silently dropped and never filled in with another layer's conclusions.

## Seven iron rules (equal in force to the redaction lines below)

1. **Assertions first** - decide "how many should have been found" before
   talking ratios. A wrong denominator makes every percentage a lie. Rather
   void the whole batch than ship half a ledger.
2. **No sampling into conclusions** - a partial result may only be labelled
   "sampled", with its denominator stated.
3. **Read traces, not declarations** - whether a scheduled task exists is a
   question about log records, not config files. Config is intent; logs are fact.
4. **Empty is not absent** - a failed request is not missing data. "Still
   failing after retries" and "confirmed 404" go into two separate buckets,
   or rate limiting gets written down as a data hole.
5. **One layer at a time** - repair advances layer by layer; verify each layer
   before touching the next. Cross-layer edits make effects unattributable.
6. **Self-tests are not verification** - the script saying pass is not
   evidence. Read back through an independent path: another entry point,
   another tool, the action a real user would take.
7. **Outputs must be recomputable** - thresholds, denominators and criteria
   versions land on disk, so today's conclusion can be reproduced months later.

## Redaction lines (scan-wide, same force as the iron rules)

The scanner's power comes from reading other people's code and data, so **its
boundary must be fixed before its capability**.

1. **Scan code, not people** - hard-excluded from scope: key files (.env,
   keys/tokens/app-secrets/passwords in config), identity-document files
   (ID/passport/bank-card images and PDFs), private data (chat logs, contacts,
   personal document folders). Rather miss it than cross the line.
2. **Environment variables: keys only, never values** - the cloud snapshot
   records variable names; the evidence column carries "key name + configured?"
   and nothing else.
3. **Data layer runs statistics only** - null rates and value domains come out
   as aggregates; sensitive field values never enter the ledger or evidence.
4. **Self-check before landing** - every script checks its out/ for plaintext
   keys and identity numbers before counting as done; sensitive intermediates
   are marked "internal, do not commit".
5. **Suspected sensitive content -> skip + INFO trace** - do not expand, copy
   or persist; one INFO line "contains sensitive field, skipped for human
   review" is the whole record.
6. **Check the fault, not the person** - when a response carries a sensitive
   field, record the field name and its existence, never the value; phrase it
   as structural evidence ("the endpoint returns this field").

## Five layers + four deep kinds

Layers follow the direction a change propagates. Layer count is a concept (5);
the implementation is 4 scanners, because runtime and schedule read the same
two inputs and were merged to remove a hidden file-order dependency.

| Layer | Scanner | Sweeps | Nature |
| --- | --- | --- | --- |
| data | scan_data.py | null rates / placeholders / value domains / consistency constraints | deterministic |
| api | scan_api.py | pagination / 404 semantics / field nulls / id holes | deterministic |
| runtime | scan_deploy.py | local source vs live deployment + source heuristics | mixed |
| schedule | scan_deploy.py | declaration / live / function-body three-way reconciliation | deterministic |
| client | scan_code.py | page inventory / route alignment / dead code / repo hygiene | mixed |
| deep | deep_scan.py | dead code / dependency cycles / complexity / silent zones | mixed |

Per-layer criteria live in references/scan-layers.md; the signal vocabulary,
fingerprint formula and thresholds live in references/signal-contract.md (the
single source of truth - no other document may re-list signal names).

## Workflow (8 steps)

1. **Create the work directory** - make `_sweep_<YYYYMMDD-HHMMSS>/` inside or
   beside the project, or pass `--work-dir <path>`. **Scripts locate themselves
   via `os.path.dirname(os.path.abspath(__file__))`, never via the caller's
   working directory** (so an installed skill survives cwd changes). All
   products (out/, ledger, baseline snapshots, undo backups) land under
   `--work-dir`, never inside the skill installation directory - the skill dir
   is read-only and lives in a plugin cache; writing user data there poisons
   the next package. This directory is an internal sensitive workspace: any
   intermediate holding env-key lists or live snapshots is marked "internal,
   do not commit"; the owner decides retention at the end.
2. **Pick the profile** - `--profile <id>` or `--profile auto`. Auto scores
   language marker files and content markers; a tie or an all-zero field exits
   2 and demands an explicit choice. Seven built-ins: generic-polyglot
   (fallback: kernel judgments only), generic-python / generic-node /
   generic-go, wechat-miniprogram, tencent-scf, fastapi-python.
3. **Run the sweep** - `python sweep.py --project-root <dir> --work-dir <dir>
   --profile <id>`. Sweep dispatches the enabled layers, then checks every
   `_done_<layer>.txt` marker. Any missing marker or complete=false aborts
   before the ledger: exit 1, no ledger. Input: project root + work dir.
   Output: per-layer findings csv + markers under out/.
4. **Read markers before rows** - a layer without a complete marker is "scan
   incomplete" (P1), never "ran, 0 findings".
5. **Aggregate the ledger** - sweep invokes ledger.py; output: ledger.csv
   (16-column contract schema, decision/owner/note left empty for humans) +
   ledger.md (sections per layer, `<layer>-NN` numbering) +
   out/baseline_<run-id>.json. Dedup key is the fingerprint only - free text
   never enters it, so rewording or moving a line cannot break dedup.
6. **Human triage** - hand the ledger over; people grade and decide. **The
   scanner never decides whether to fix.** Decisions typed into ledger.csv are
   carried forward by fingerprint on the next run and excluded from the
   baseline, so "confirmed non-issue" stops recurring.
7. **Repair layer by layer** - one layer at a time, verified through the
   original entry point after each. Paradigm index: command-style (one AI,
   one instruction, verify before the next), staged-script (server/database
   high-risk: stage0 backup probe, stage-by-stage, rollback point per stage),
   freeze-order (multiple AIs on one environment: stop writes first, forbidden
   list, evidence-based correction), review-decide-seal (pre-release: review
   admits fault before deciding, only the named scope moves, single exit).
   Repair iron rules: back up first; only fill empties, never overwrite
   (COALESCE(NULLIF(col,''), new) shape); minimal change, single duty, every
   line explainable - stop and report if more must move; never fill in secrets
   on the user's behalf, stop and ask the owner; stop the moment verification
   fails. Full templates: references/repair-patterns.md. Rollback:
   `python undo.py backup --root <dir> --paths <p1,p2,...> --work-dir <dir>`
   before touching code.
8. **Deep scan + architecture buffer** - `deep_scan.py --kinds
   deadcode,dependency,complexity,silent` (one script, one shared parse).
   Complexity is calibrated, not hardcoded: n<30 uses the absolute floor,
   otherwise max(floor, P95), every finding carries threshold + source.
   Silent-zone hits are candidates only - the script never grades them; the
   model judges "intentional vs swallowed", the human assigns severity.
   Before any architecture change: aggregate evidence (ledger.py --view
   proposal) -> the model writes three suggestions ranked by gain/risk plus
   "other" -> the user picks one (and only that one gets executed) -> repair
   -> verify -> undo fallback (undo.py restore, per-item sha256 verification,
   honest partial-failure reporting).

## Definition of Done

A run counts as complete only when all of these hold: every enabled layer has
a `_done_<layer>.txt` with complete=true; marker finding counts equal the csv
row counts; ledger.csv exists with the 16-column contract schema; the
redaction self-check found nothing; no product landed inside the skill
directory; and the sweep summary states every skipped layer with its reason.

## Stop and ask a human when

1. A required input is missing and no safe default exists (no default domain,
   no guessed snapshot path).
2. Auto profile detection ties or scores zero.
3. A layer reports complete=false or its marker is missing.
4. A finding would touch a secret, credential or private field.
5. The planned repair exceeds "fill the empty, minimal change" - more code
   must move than the instruction named.
6. Verification fails after a repair stage.
7. The architecture suggestion ranking is contested, or the user picks
   "other".
8. A forbidden fixture-style false positive appears (the C16 gate's
   bidirectional assertion failed) - stop and fix the criteria, do not
   "fix" the assertion.

## Script invocation

```bash
python sweep.py --project-root <dir> --work-dir <dir> --profile <id|auto>
python scan_data.py  --db <path> --project-root <dir> --work-dir <dir> [--table T]...
python scan_api.py   --base <url> --work-dir <dir> [--paths-file <json>] [--id-range 1-280]
python scan_deploy.py --root <src> --live <snapshot.json> --layers runtime,schedule --work-dir <dir>
python scan_code.py  --root <client-dir> --project-root <dir> --work-dir <dir>
python deep_scan.py  --root <src> --kinds deadcode,dependency,complexity,silent --work-dir <dir>
python ledger.py     --work-dir <dir> [--view ledger|proposal|diff] [--previous <baseline.json>]
python undo.py       backup --root <dir> --paths <p1,p2> --work-dir <dir>
python undo.py       restore --snapshot <work-dir>/undo/<id> [--force]
python selftest.py   --skill-dir <dir>            # 13 gates incl. the C16 smoke
```

Every script: stdlib-only Python 3.11+, `main()` + `if __name__ ==
"__main__"` guard, exit 0 complete / 1 incomplete-or-verify-failure /
2 input error, products in overwrite mode (same input twice -> byte-identical
products). Usage help: `<script> --help`; self-check: `<script> --selftest`.

## Outputs and where they land

All under <work-dir> (never the skill dir): out/findings_<layer>.csv
(16-column contract), out/metrics_<layer>.json, out/_done_<layer>.txt,
ledger.csv, ledger.md, out/baseline_<run-id>.json,
out/baseline_diff_<run-id>.md, out/thresholds_<run-id>.json,
undo/<id>/manifest.json + mirror/. Field definitions and grading:
references/ledger-and-triage.md.

## Reference index

- references/signal-contract.md - signal vocabulary, fingerprint, gate-11
  assertion criteria (single source of truth; other docs link, never copy)
- references/scan-layers.md - per-layer criteria incl. the four deep kinds
- references/false-positives.md - fourteen measured false-positive classes
- references/silent-failures.md - six silent-failure forms and their
  verification paths ("did the effect appear", not "did it error")
- references/ledger-and-triage.md - field contract, grading, four triage
  decisions, baseline diff buckets
- references/repair-patterns.md - four paradigms + repair iron rules +
  suggestion template + buffer flow + undo semantics
- references/profiles.md - profile mechanism, kernel/platform boundary,
  the seven presets, how to add one, degradation behaviour
- references/thresholds.md - dual-condition calibration, floor rationales,
  three hard rules
- references/factory-inspection-report.md - v2.0.0 real-install + real-trigger
  inspection report (factory license)

## Factory Inspection Report (factory license)

v2.0.0 has been verified with a **real install + real trigger**. Full evidence and
reproducible commands are in `references/factory-inspection-report.md`: scan_code
0 findings (pure-backend project, client layer clean, as expected) + sweep 5
findings (data 1 + deep 4) raw output, both editions selftest 13/13, calibration
18/18. Verdict: **both editions passed inspection, cleared for delivery.**

## Known limitations

1. **Layers without `roots.*` skip by default**: when a profile declares no
   `roots.client` / `roots.api` / `roots.runtime` / `roots.schedule`, that layer
   is `enabled_by_default:false` and skips by design, logging the reason (never
   silently guesses, never downgrades). Example: `generic-python` enables only
   `data`+`deep`.
2. **fastapi-python client layer needs explicit enable**: frontend (Vue) scanning
   depends on `roots.pages_dir` / `routes_manifest`; it is `enabled_by_default:
   false` and only scans pages/routes after you pass `--override` to configure
   them. A pure-backend FastAPI project loses nothing — data / runtime / deep
   coverage is unaffected.
3. **data layer needs explicit `--db`**: without `--db` the data layer skips
   explicitly and logs the reason; no default database is built in.
4. **API layer has no built-in default domain**: missing `--base` skips the API
   layer (the contract forbids a built-in default domain).
5. **runtime/schedule layers need `--live`**: missing it skips — never downgrades
   to "local scan only".
