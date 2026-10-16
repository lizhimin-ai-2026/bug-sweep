# bug-sweep Signal Contract v1.0

> This file is part of the skill: it is the single source of truth for the public
> signal vocabulary, the fingerprint formula, and gate 11 (C16 smoke) assertions.
> The manifest, this file, and selftest.py gate 11 must stay byte-consistent;
> other documents may only link here and must not re-list signal names.

## 1. Naming rules

- Format: <layer>.<subtype>; layer in {data, api, runtime, schedule, client, deep}.
- deep.* is the deep-scan AST namespace (distinct from scan_deploy regex-level
  heuristics); data.* is the data layer; the rest keep their original names.
- Four fixed names (never rename): deep.silent.empty_catch / deep.dep.cycle /
  deep.complexity.long_fn / data.placeholder_hit.
- New signals enter this table before they enter code; bump
  signal_schema_version on any vocabulary change and mark old baselines stale.

## 2. Fingerprint (the sole anchor for baseline and dedup)

```
fingerprint = sha1(layer_group | normalized_path | signal | anchor)[:16]
```

- layer_group: fixed to "deep" for deep.* signals; otherwise resolved via the
  profile ownership path rules, falling back to the producing layer.
- normalized_path: "/" separators, line-number suffixes stripped (:42 / #L12),
  dot segments collapsed (a/./b -> a/b).
- Line numbers and measured values are excluded: symptom / evidence /
  threshold / loc_line never enter the fingerprint.
- sweeplib.fingerprint() is the only implementation in this repo; no script
  may assemble its own hash.

## 3. Complete signal list

### 3.1 Data layer (scan_data.py)

| signal | meaning | anchor | severity policy |
| --- | --- | --- | --- |
| data.empty_field | column null ratio over threshold | <table>.<column> | >=99.5% all-null P1; >=50% P1; >=20% P2 |
| data.empty_table | table has zero rows | <table> | P2 |
| data.placeholder_hit | whole-word placeholder in a column value | column name | to-verify/to-measure P1; else P2 |
| data.constraint_violation | consistency constraint broken | constraint id | as declared in the constraint file (P0/P1) |
| data.constraint_error | constraint SQL itself failed to run | constraint id | P1 |
| data.constraint_ok | consistency constraint verified | constraint id | INFO |
| data.count_mismatch | --expect-total count mismatch | <table> | P1 |
| data.table_missing | explicitly requested table absent | <table> | P1 and complete=false |
| data.table_unreadable | table exists but cannot be read | <table> | P1 |
| data.field_unreadable | column cannot be read | <table>.<column> | P1 |
| data.sensitive_skipped | sensitive column skipped for value scan | <table>.<column> | INFO (redaction red line) |

### 3.2 API layer (scan_api.py)

| signal | meaning | anchor | severity policy |
| --- | --- | --- | --- |
| api.not_found_semantics | missing resource did not return 404 | probe path | P2 |
| api.id_gap | id hole (confirmed 404, not a failure) | id | P2 |
| api.field_empty | field null ratio over threshold while walking ids | <path>.<field> | P2 |
| api.incomplete | completeness assertion failed | range | P1 and complete=false |
| api.path_error | probe path did not return 200 (still failing after retries, bucketed apart from 404) | probe path | P2 |
| api.bad_json | response body is not JSON | probe path | P2 |
| api.total_mismatch | response total differs from the expected value | probe path | P1 |
| api.field_missing | response lacks a contracted field | <path>.<field> | P2 |
| api.id_walk_failures | id walk still has failures after retries | range | P2 |

### 3.3 Runtime layer (scan_deploy.py --layers runtime)

| signal | meaning | anchor | severity policy |
| --- | --- | --- | --- |
| cloud.ghost_fn | deployed in cloud, no local source | function name | P1 |
| cloud.undeployed | local source, not deployed | function name | P2 |
| config.drift | local declaration differs from cloud reality | function name | P2 (needs false-positive rule 8 derivation) |
| env.missing | secret-class env var missing in cloud | var name | P1 |
| env.not_set | non-secret var missing (works via fallback) | var name | P2 |
| env.channel_mismatch | dual config channels without load_dotenv() | file path | P2 |
| secret.literal | suspected hardcoded secret in source | file path | P0; evidence may only carry offset + length + type |
| guard.bypass | write-protection gate defeatable by a switch | switch name | P1 |
| src.async_unawaited | suspected async call without await | function qualified name | P2 (always "suspected") |

### 3.4 Schedule layer (scan_deploy.py --layers schedule)

| signal | meaning | anchor | severity policy |
| --- | --- | --- | --- |
| trigger.cloud_only | exists in cloud, not declared locally | trigger name | P1 |
| trigger.local_only | declared locally, absent in cloud | trigger name | P2+ (check logs) |
| trigger.body_no_handler | timer branch in body, no trigger on either side | function name | P1 (entry with event param exempt) |
| cron.malformed | cron field count differs from profile | trigger name | P2 |
| schedule.log_evidence_needed | log evidence required | trigger name | INFO |

### 3.5 Client layer (scan_code.py)

| signal | meaning | anchor | severity policy |
| --- | --- | --- | --- |
| page.incomplete | page directory missing entry file | page dir | P2 |
| route.dangling | route points at a missing page | route path | P1 |
| route.unregistered | page exists but route unregistered | page dir | INFO |
| route.manifest_broken | route manifest unparseable | file path | P0 and complete=false |
| deadcode.fn | exported function never referenced | function qualified name | P2 |
| bak.file | backup file not covered by both ignore rules | file name | neither P1; one P2 |
| client.placeholder_hit | whole-word placeholder in source (distinct from data.placeholder_hit db scan) | hit symbol/field name | INFO (manual confirmation) |
| todo.marker | leftover TODO/FIXME/XXX marker | marker word | P2 |
| share.matrix | share capability matrix (paired capability missing) | page | INFO |

### 3.6 Deep scan (deep_scan.py, layer_group fixed to deep)

| signal | meaning | anchor | severity policy |
| --- | --- | --- | --- |
| deep.deadcode.fn | function unreachable from entries | qualified name module.Class.method | P2; dynamic reference downgrades to INFO |
| deep.deadcode.module | module never imported | module name | INFO (entry registration is often dynamic) |
| deep.dep.cycle | module dependency cycle | sorted cycle notation a->b->a | 2-node direct cycle P1; >2 nodes P2; lazy-import-only P2 "cycle mitigated" |
| deep.complexity.long_fn | function line count over threshold | qualified name | P2 |
| deep.complexity.deep_nesting | nesting depth over threshold | qualified name | P2 |
| deep.complexity.high_mccabe | cyclomatic complexity over threshold | qualified name | P2 |
| deep.complexity.dup_block | duplicated code block | fnA\|fnB (sorted qualified names) | P2 |
| deep.silent.empty_catch | empty catch / except pass | enclosing qualified name | P2; explanatory comment downgrades to INFO |
| deep.silent.fallback | fallback passthrough (missing key returned as-is) | enclosing qualified name | P2 |
| deep.silent.err_discard | Go err explicitly dropped / bare recover | enclosing qualified name | P2 |

### 3.7 Ledger aggregation (ledger.py)

| signal | meaning | anchor | severity policy |
| --- | --- | --- | --- |
| ledger.incomplete | layer completion marker missing / complete=false / marker count mismatch | layer id | P1; exit 1, the ledger is still written but must not be read as a complete conclusion |

## 4. Gate 11 (C16 smoke) assertion criteria

```
actual   = { f.fingerprint for f in ledger.csv if f.severity in {P0,P1,P2} }
expected = { sweeplib.fingerprint(layer_group(p), p.path, p.signal, p.anchor)
             for p in manifest.planted }
assert actual == expected          # both directions: miss = criteria broken;
                                   # unplanned entry = signal-to-noise collapse
for f in manifest.forbidden: assert fingerprint(f) not in actual
```

- layer_group(p): signal starting with deep. -> deep; otherwise resolved via
  profile ownership, falling back to the producing layer.
- INFO-level entries are tolerated; out-of-scope INFO is a warning, not an error.
- auto round: --profile auto must SELECT manifest.expect_profile (not merely
  "not error").

## 5. Fixture authoring requirements

1. Every fixture carries both planted and forbidden; the assertion target is
   the actual/expected pair above.
2. Language marker files (auto detection depends on them; miss one and the
   auto round picks the wrong profile): smoke-python needs pyproject.toml or
   requirements.txt at the project root and must not contain fastapi imports
   (otherwise fastapi-python outranks it); smoke-node needs package.json;
   smoke-go needs go.mod.
3. data.placeholder_hit may only come from the scan_data database scan
   (anchor=column name, path=database file relative to the project root).
   The generic-* profiles convention for roots.db is app.db; plant a sqlite
   app.db at the project root with a whole word (3+ chars) in a TEXT column.
4. Legal empty catch: deep.silent.empty_catch reports P2 for uncommented empty
   catches; an explanatory comment inside the except/try block downgrades to
   INFO. Forbidden cases must be constructed with the comment.
5. deep.complexity.long_fn has an absolute floor of 40 lines; planted long
   functions must exceed 40 lines, all others stay <=40 lines, McCabe <=10,
   nesting <=3.
6. Placeholder regression: forbidden must include a "real place name that
   happens to contain a single character" case, asserting whole-word matching
   does not misfire.
7. deep.dep.cycle planted cycles must be module-level import cycles (two files
   importing each other); function-level lazy imports downgrade to P2
   "cycle mitigated".
8. Manifest fields: fixture_id / language / expect_profile / planted[] /
   forbidden[] (each with signal / path / anchor / note), plus
   auto_detect_must_be_unambiguous: true.

## 6. Threshold criteria (deep-scan heuristics)

| signal | absolute floor | rationale |
| --- | --- | --- |
| function lines | 40 | below this a function cannot be "too long" |
| nesting depth | 3 | mainstream indentation-style consensus |
| cyclomatic complexity | 10 | modularization upper bound from McCabe's original paper |
| duplicate block | 12 lines and 0.85 similarity | below 12 lines statistical noise dominates; 0.85 separates true duplication from shared templates |

Dual condition: n<30 -> absolute floor; P95 < floor -> floor;
otherwise max(floor, P95). Every finding must carry threshold and
threshold_source (recomputability hard rule).

## 7. signal_schema_version (vocabulary version stamp)

- `signal_schema_version` is the contract / vocabulary schema version stamp.
  Current value: `"1.0"` (defined as `S.SIGNAL_SCHEMA_VERSION` in `sweeplib.py`).
- Carrier: `ledger.py` writes it into the top-level baseline JSON (`"signal_schema_version"`
  key, see `ledger.py:335`). On a re-run, if the previous baseline's stored value differs
  from the current value, `ledger.py` emits a `stale_baseline` warning and marks the prior
  baseline stale — it never silently treats an old-vocabulary baseline as "resolved".
- Bump rule: increment on any vocabulary change (new / renamed signal, or an anchor or
  severity-policy change in §3). When bumped, old baselines are explicitly marked
  `stale_baseline: true` and the diff report flags the version gap at the top.
- This release: the vocabulary is unchanged from v1.0, so `signal_schema_version` stays
  `"1.0"`; no baseline is marked stale.
