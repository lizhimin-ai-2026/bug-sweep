# Fourteen measured false-positive classes

> Read this before adding any criterion. Heuristic scanning always produces
> false positives; a ledger with thirty percent noise gets skimmed once and
> abandoned - worse than not scanning, because it burned trust. Numbers below
> are measured evidence from real repair sessions (project identity removed);
> they are why each criterion is calibrated the way it is.

## 1. "Environment variable missing" (fallback writings)

A var that looks unconfigured may have a working fallback in code. The four
fallback writings must all be recognised before reporting env.missing:
`||` default, `!==` / `===` guard, `?` ternary. Key-class vars -> P1;
vars with a fallback -> P2 (env.not_set). Anything else is a false P1.

## 2. "Async function called without await"

Always write "suspected" (src.async_unawaited, P2 candidate). Fire-and-forget
is a legitimate pattern (telemetry, cache warm-up); the script emits the
candidate line, the model judges "forgotten vs deliberate", the human grades.

## 3. "Copy residue / placeholder words"

Whole-word matching only, and the word table admits nothing shorter than 3
characters (a single character can never be delimited inside a longer word -
a real island name containing one character must not hit). Only SELECT-style
evidence; never emit UPDATE; user-visible copy vs internal constants is a
human call (INFO until confirmed).

## 4. "Trigger configured but the cloud list is empty"

A configured-but-invisible trigger is usually a listing limitation, not a
missing trigger. Check the schedule log values first (TRIGGER_TIMER /
TCB_API / wx_trigger); only report trigger.cloud_only with the derivation
written out.

## 5. "Id holes / missing data" (batch walking)

Failed requests are not missing records. "Still failing after retries" and
"confirmed 404" go to two buckets; the completeness assertion
(success + 404 + failed == range length) must pass or the layer reports
incomplete. Contiguous failure segments are rate limiting; scattered points
are network jitter - the segment analysis says which.

## 6. "Backup files shipped in the package"

Check every ignore-rule location first (.gitignore plus the platform pack
ignore): covered by all -> silent, covered by all but one -> P2, covered by
none -> P1. "Looks dirty but cannot enter the package" is the classic
cross-layer noise generator.

## 7. Judging "deliberate exemption" as "missing"

Some absences are by design. Share capabilities come in pairs
(onShareAppMessage x onShareTimeline): scan the full matrix, report only the
asymmetric pages as INFO for human exemption marking. Same family:
permission declarations, telemetry events, i18n keys, route names. A table
that only reports "missing" cannot be triaged.

## 8. "Local declaration differs from cloud reality" is not a defect

Local config says A, cloud says B: that only proves "not deployed" - a todo,
not a bug. Report only after deriving three steps: the cloud value is wrong
AND the actual requirement differs AND the drift has user-visible effect
(config.drift, P2 with the derivation note).

## 9. Sampling is not a full pass

A partial result may only be labelled "sampled" with its denominator stated.
Turning a 94/279 sample into a "full null rate" is this method's easiest
fatal mistake; the denominator enters every percentage.

## 10. "Config exists but cannot be read" (channel mismatch)

A pydantic Settings(.env) project plus os.environ readers means .env never
reaches os.environ - a permanent false positive unless load_dotenv() exists.
Detect dual channels plus the loader before reporting env findings
(env.channel_mismatch, P2).

## 11. Null rate is not a defect (align with display slots)

An empty column whose front end never displays is not a bug. The script
emits the aggregate plus "display slot unknown"; the model reads the code,
the human grades. >=99.5% all-null P1, >=50% P1, >=20% P2 - thresholds, not
verdicts.

## 12. Auth error is not "function never ran" (attribute by stage)

Locate the stage first (auth / route / function body), then attribute. An
auth failure upstream of a handler says nothing about the handler; blaming
the wrong stage invalidates the whole conclusion.

## 13. Write-protection bypassed by "unprotecting"

A guard switch that disables the guard (guard.bypass, P1) is a finding about
the switch, not the protection it bypasses - check whether the switch is
reachable from user input before grading.

## 14. When unsure

Downgrade to INFO with "needs human confirmation". Never fabricate a P1.
Every criterion this table earned came from one real misfire; add new ones
here after each round (workflow step 7) - the ledger expires, this table
does not.
