# Thresholds: dual-condition calibration

## Why calibrated, not hardcoded

Pure hardcoding fails across projects; pure P95 fails within one - when a
project is uniformly bad, P95 rises and the scanner paralyzes itself. The
ruling: absolute floors unioned with the project P95, under two conditions.

```
first pass (--calibrate-only): metrics per function + P50/P90/P95/P99/max
second pass (judging):
  n < 30            -> threshold = floor; source = absolute-floor (n<30)
  P95 < floor       -> threshold = floor; source = absolute-floor (P95<floor)
  otherwise         -> threshold = max(floor, P95); source = percentile-p95
  user override     -> threshold = override;  source = user-override
```

## Absolute floors and their defenses

| Signal | Floor | Rationale |
| --- | --- | --- |
| function lines | 40 | below this a function cannot be "too long" |
| nesting depth | 3 | mainstream indentation-style consensus, not taste |
| cyclomatic complexity | 10 | modularization upper bound from McCabe's original paper |
| duplicate block | 12 lines and 0.85 similarity | below 12 lines statistical noise dominates; 0.85 separates true duplication from shared templates (a single 0.80 condition flags every same-directory template) |

## Three hard rules

1. Thresholds act on heuristic criteria only (complexity, similarity).
   Deterministic criteria (404, all-null column, dangling route, dependency
   cycle) are set relations, not quantity relations - no threshold touches
   them.
2. Every finding carries threshold and threshold_source and writes them into
   evidence. Reproducing today's conclusion three months from now requires
   knowing where the threshold came from.
3. Solved thresholds land on disk (thresholds_<run-id>.json) and are
   recorded in the baseline. A threshold change across runs is itself a
   signal - it explains most "resolved" bucket entries.

## Overriding

`--thresholds <json>` (e.g. {"fn_lines": 60}) replaces solved values and
stamps source=user-override, so an overridden finding stays recomputable.
User overrides merge per signal; anything not mentioned keeps the solved
value.
