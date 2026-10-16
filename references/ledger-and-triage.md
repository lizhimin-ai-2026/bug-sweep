# Ledger, triage and baseline diff

## Field contract (16 columns, one schema repo-wide)

fingerprint / signal / anchor / layer / source / severity / threshold /
threshold_source / path / loc_line / category / symptom / evidence /
decision / owner / note.

- fingerprint: sha1(layer_group | normalized_path | signal | anchor)[:16],
  the only dedup and baseline key. Line numbers and measured values are
  excluded by design: a defect that slides down three lines after an
  unrelated edit keeps its identity.
- layer: resolved by the profile ownership rules (path -> layer), falling
  back to the producing layer. deep.* signals are fixed to deep.
- source: which scanner produced it, multi-valued when two scanners agree.
- severity: initial grade, for ordering attention only.
- threshold / threshold_source: heuristic criteria only; the recomputability
  hard rule.
- decision / owner / note: the human's three columns, empty at delivery.

## Grading

P0 broken protection / leaked secret / corrupt route manifest.
P1 defect with user-visible effect, or scan-incomplete.
P2 candidate needing confirmation, or heuristic over threshold.
INFO baseline record, deliberate exemption, dynamic-reference dead code.

## Four triage decisions

fix (schedule into the layer batch) / won't-fix (write the reason in note -
the entry then leaves the baseline and stops recurring) / later (defer with
owner) / downgrade (re-grade with justification). The scanner never decides;
decision is the only column a human may write, and the ledger carries it
forward by fingerprint on the next run.

## Baseline diff (four buckets)

new (this run only) / persisting (both runs, with age_runs = consecutive
run count - the answer to "the same bug for three days running") / resolved
(last run only; a threshold change explains most of these) / regressed
(both runs, severity rose). Two hard rules: age_runs >= 3 with an empty
decision gets a ledger hint ("fix it, or write down why not"); entries with
a non-empty decision leave the baseline. A signal-vocabulary change bumps
signal_schema_version and marks old baselines stale - never silently
report "resolved" against a different vocabulary.

## Views

ledger (default): ledger.csv + ledger.md, sections per layer ordered by the
profile, `<layer>-NN` numbering for verbal reference.
proposal: aggregated deep-scan evidence only - the script aggregates, the
model writes the three suggestions, the human picks one or "other".
diff: the four buckets against --previous, plus a fresh baseline snapshot.

## Delivery shape

ledger.csv is the working artifact (spreadsheet-grade, utf-8-sig); ledger.md
is the human read. Incomplete layers abort the batch: rather void the whole
ledger than ship half of one - a missing completion marker is P1 "scan
incomplete", never a silent zero.
