# ALL Bug Sweep (全栈卫士)

Layered defect sweep and silent-failure detection for any stack: five scan
layers (data/API/runtime/schedule/client) plus four deep kinds (dead code,
complexity, dependency cycles, silent zones), one fingerprint-based ledger.

- Recomputable: fingerprint = sha1(layer_group | normalized_path | signal | anchor); line numbers and measured values never enter it.
- Honest: a missing completion marker is P1 "scan incomplete", never zero; incomplete batches void the whole ledger.
- Redaction first: keys only never values; a pre-disk gate aborts on credential-like text.
- Zero dependencies (Python 3.11+ stdlib); seven profiles carry every platform fact; copy-semantics undo with per-item sha256 verification.

## Quick start

```bash
python scripts/sweep.py --project-root <dir> --work-dir <dir> --profile auto
python scripts/selftest.py --skill-dir .     # 13 gates, incl. C16 smoke
```

Docs: SKILL.md (execution contract) + references/ (criteria, signal contract,
profiles, thresholds). Chinese twin, identical capabilities: bug-sweep-cn
(language + default profile only). License: MIT.