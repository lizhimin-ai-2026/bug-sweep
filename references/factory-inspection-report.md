# Factory Inspection Report（English edition bug-sweep v2.0.0）

> This file is the skill's "factory license / inspection certificate". Iron rule
> from laoli: real install + real trigger, report written into the skill,
> accountable to ourselves and to the user.
> Capability-identical to the Chinese `bug-sweep-cn`; language and default
> profile are the only differences. Conclusions here apply to both editions.

---

## 1. Inspection target

| Item | Value |
| --- | --- |
| Skill | bug-sweep (ALL Bug Sweep · English OSS edition) |
| Version | 2.0.0 |
| Runtime | Python 3.13.12 (managed, stdlib-only, zero third-party deps) |
| Real install path | `.workbuddy/skills/bug-sweep/` (project-level, installed via cp -r) |
| Companion CN edition | `.workbuddy/skills/bug-sweep-cn/` (bug-sweep-cn v2.0.0, scripts byte-identical) |
| Legacy top-level | preserved untouched (big-co methodology: low version fully OSS, high version semi-OSS) |

## 2. Real trigger method (reproducible)

### 2.1 scan_code (client layer standalone, pure-backend project)
```
python <SKILL_DIR>/scripts/scan_code.py \
  --root         <FIXTURE>/smoke-python/app \
  --project-root <FIXTURE>/smoke-python/app \
  --work-dir     <TEMP>/bugsweep_real_code
```
`FIXTURE = 03-源码/bug-sweep/tests/fixtures`. `scan_code` parses a pure-backend
project with no frontend pages/routes.

### 2.2 sweep (orchestrated, profile=generic-python -> data+deep enabled by default)
```
python <SKILL_DIR>/scripts/sweep.py \
  --project-root <FIXTURE>/smoke-python \
  --profile      generic-python \
  --work-dir     <TEMP>/bugsweep_real_sweep
```
> generic-python enables only `data`+`deep` by default (client/api/runtime/schedule
> have no `roots.*` configured, so they skip per design and log the reason).
> fastapi-python additionally enables `runtime`; its `client` layer is
> `enabled_by_default:false` and requires `--override` with `pages_dir`/
> `routes_manifest` to activate (see SKILL.md "Known limitations").

## 3. Raw output evidence

### 3.1 scan_code
```
scan_code done: pages=0 routes=0 findings=0 complete=true
CODE_EXIT=0
```
Product `out/findings_client.csv` has only the header row (16-column contract),
no data rows — pure-backend project, 0 client-layer hits, as expected.

### 3.2 sweep
```
sweep: profile=generic-python ... layers=data,deep
[data] ok: 1 finding(s), complete=true
[deep] ok: 4 finding(s), complete=true
ledger: 5 entries (0 incomplete-marker P1) -> <TEMP>/bugsweep_real_sweep/ledger.csv | ledger.md
ledger: baseline snapshot: <TEMP>/bugsweep_real_sweep/out/baseline_a911255c42a0.json (4 findings)
sweep done: ledger at <TEMP>/bugsweep_real_sweep/ledger.csv
SWEEP_EXIT=0
```
Products complete: `findings_data.csv` / `findings_deep.csv` / `ledger.csv` /
`ledger.md` / `baseline_a911255c42a0.json` / `metrics_data.json` /
`metrics_deep.json` / `thresholds_dc06d235497a.json` / `_done_data.txt` /
`_done_deep.txt`.

## 4. Five real findings, line by line

| # | signal | layer | severity | path | anchor | symptom / evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `data.placeholder_hit` | data | **P1** | app.db | remark | field `notes.remark` mixed with placeholder word "待补充" (whole-word hit 1 row; SELECT only, no UPDATE — human decides what to change) |
| 2 | `deep.dep.cycle` | deep | **P1** | app/svc_b.py | svc_a->svc_b->svc_a | module cyclic dependency (2-node direct cycle) |
| 3 | `deep.complexity.long_fn` | deep | P2 | app/handler.py | handler.handle_batch (L16) | function over length threshold: value=46 / threshold=40 (n=11<30, percentile unreliable, absolute floor used) |
| 4 | `deep.silent.empty_catch` | deep | P2 | app/svc_a.py | svc_a.load_config (L7) | bare `except` with no comment, error silently swallowed |
| 5 | `deep.silent.empty_catch` | deep | INFO | app/handler.py | handler.telemetry (L8) | `except` with explanatory comment, likely intentional ignore (excluded from baseline) |

> Baseline `baseline_a911255c42a0.json` records 4 findings (the INFO-level #5
> excluded), consistent with the rules.

## 5. Conclusion (passed for release)

1. **Real install**: both editions v2.0.0 installed to `.workbuddy/skills/`;
   legacy top-level preserved untouched.
2. **Real trigger**: scan_code 0 findings (pure-backend project, client layer
   clean, as expected); sweep 5 findings (data 1 + deep 4), both `exit 0`,
   products complete and reproducible.
3. **Calibration intact**: `calibration/校准报告.md` 18/18 real bugs hit, both
   editions identical; `selftest.py` 13/13 gates both editions (incl. C16 smoke).
4. **Vocabulary version**: `signal_schema_version="1.0"`, held at 1.0 this round,
   no stale warning triggered.
5. **Criterion solidified**: rule-7 new acceptance criterion (~22-25 statically
   detectable bugs, hit >=18 = pass) solidified in `calibration/校准报告.md` and
   `04-QA/阶段1验收报告_v0.1.md`.

**Verdict: v2.0.0 both editions passed inspection, cleared for delivery.**

---
*This report is transcribed directly from real run artifacts, not simulated.
Reproduce with the commands in section 2.*
