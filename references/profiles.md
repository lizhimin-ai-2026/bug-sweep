# Profiles: mechanism, presets and degradation

## Kernel vs platform-specific

The dividing question: after switching platforms, does this criterion's
CONCLUSION change? If yes it belongs to a profile; if no it is kernel.
Kernel: file traversal and ignore-rule evaluation; metric computation
(lines / nesting / McCabe / similarity / reachability / SCC); rate limiting
and backoff; failure-vs-404 bucketing; completeness assertions; the ledger
schema and fingerprint; baseline diff; snapshot and rollback; the redaction
gate; threshold solving. Platform-specific: directory layout and roots,
entry-file names, route manifest and field paths, pack-ignore locations,
log-evidence values, async hint words, the placeholder word table, cron
shape, expected values, path ownership, sensitive field patterns.

Profiles are JSON, not YAML: the managed runtime has no PyYAML, and the
zero-dependency rule outranks convenience. A user-handed YAML file is
refused with a clear error, never silently attempted.

## Structure (schema 1.0)

schema_version / id / display_name / detect (priority, any_files, all_files,
content_markers) / roots (client, runtime, pages_dir, routes_manifest,
api_module, ignore_rules, db, live_snapshot) / entry_files / ownership
(path -> layer globs) / layers (id, order, display_name,
enabled_by_default, skip_reason) / signals (placeholder_words,
sensitive_field_patterns, async_call_hints, key_consts, timer_hints,
domain_fields) / cron / thresholds / evidence / live_snapshot. Missing
required keys exit 2 with the JSON path; the loader never guesses.

## The seven presets

- generic-polyglot - fallback / explicit degradation: kernel judgments only
  (complexity, cycles, silent zones, dead code); all five platform layers
  carry skip_reason "platform specialization not configured". Use it when
  the platform is unknown and a partial answer beats none - the ledger
  header states it does not cover data consistency, API contract or
  schedule consistency.
- generic-python / generic-node / generic-go - data + deep layers, the
  language marker file drives auto detection; generic-go rewrites the
  silent-zone criteria for explicit error returns.
- wechat-miniprogram - all five layers (api off until --base); four-file
  page entries, dual ignore rules, cloudfunctions owned by runtime, 7-field
  cron, WeChat log-evidence values.
- tencent-scf - runtime + schedule + deep; exports.main entry signature,
  triggers field, runtime/timeout/memory drift; no client layer.
- fastapi-python - data + runtime + deep; dual config-channel judgment
  (pydantic Settings vs os.environ), lazy-import cycle mitigation, no
  schedule layer by default; Vue frontend scanning needs roots.pages_dir /
  routes_manifest via --override.

## Auto detection

Scoring: any_files +10 each, all_files (complete set) +20, content_markers
+5 each, plus detect.priority - and priority only counts when something
actually matched (an unconditional priority would make a high-priority
profile win on unrelated projects, the silent fallback the contract
forbids). Highest unique score wins and is printed; a tie or an all-zero
field exits 2 with the candidate list. The fallback hint names
generic-polyglot explicitly.

## Adding a profile

Copy the closest preset, change id (must match the file name), rewrite
detect and roots, keep the required keys. Profiles are data, not code: a
community PR changes JSON, never Python. Validate with
`python profile.py --profile <id> --dump-effective`; the gate loads all
built-ins on every selftest run.

## Degradation behaviour

Three paths, all explicit: auto tie -> exit 2 with candidates; auto zero ->
exit 2 naming generic-polyglot; explicit generic-polyglot -> runs, with the
ledger header fixedly declaring the uncovered defect families. What never
happens: silently falling back to a platform profile on an unknown project -
every row it produced would be noise the user cannot recognize.
