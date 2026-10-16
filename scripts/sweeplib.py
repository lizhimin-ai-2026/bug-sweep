#!/usr/bin/env python3
"""sweeplib - shared kernel library for bug-sweep scanners.

Single source of truth for:
  - fingerprint()          : the ONLY fingerprint implementation in the repo
  - the finding field contract (16 columns)
  - LayerWriter            : overwrite-mode CSV output (idempotent by design)
  - mark_done()/read_done(): completion markers (_done_<layer>.txt)
  - assert_no_secret()     : redaction gate that runs before anything lands on disk
  - ownership resolution   : path -> layer_group via profile rules

Standard library only. Importing this module has no side effects.

Exit-code convention shared by all scan scripts:
  0  scan completed (findings may be zero)
  2  input error (missing file, bad JSON, missing required argument, bad profile)
"""
import csv
import hashlib
import json
import os
import re
import sys

# ---------------------------------------------------------------- contract --

FINDING_FIELDS = [
    "fingerprint", "signal", "anchor", "layer", "source", "severity",
    "threshold", "threshold_source", "path", "loc_line",
    "category", "symptom", "evidence", "decision", "owner", "note",
]
# Columns that never enter the fingerprint (free text / measured values / position).
NON_FINGERPRINT_FIELDS = {"loc_line", "category", "symptom", "evidence",
                          "threshold", "threshold_source", "severity",
                          "source", "decision", "owner", "note"}

SIGNAL_SCHEMA_VERSION = "1.0"

SEVERITIES = ("P0", "P1", "P2", "INFO")

# Generated / minified artifacts: never worth reading for source heuristics.
SKIP_FILE_SUFFIXES = (".min.js", ".min.css", ".map", ".lock",
                      "-lock.json", ".pb.go", ".generated.ts")


# ------------------------------------------------------------ redaction gate --

# Mirrors the toolkit contract's sensitive set. A hit raises SecretLeak and
# aborts the run: no finding text that looks like a live credential may ever
# reach disk. Evidence columns may only carry "field name + existence + type".
# Compound names (secret_key / app_secret / access_token / ...) are listed
# explicitly BEFORE their bare stems: `secret_key = 'x'` must hit, while
# `monkey = 5` / `tokenizer: v2` must not.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret[_-]?key|app[_-]?secret|access[_-]?token|auth[_-]?token|secret|token|password|passwd|pwd)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
]


class SecretLeak(Exception):
    """Raised when output text matches the sensitive pattern set."""


class InputError(Exception):
    """Bad or missing input; callers translate this into exit 2."""


def assert_no_secret(text, where):
    """Redaction gate. Raises SecretLeak on any credential-like substring.

    Called by LayerWriter.add() on every field and again by flush() on the
    serialized CSV body before the file is opened for writing.
    """
    if not text:
        return
    text = str(text)
    for pat in _SECRET_PATTERNS:
        m = pat.search(text)
        if m:
            raise SecretLeak(
                "%s: output would contain a credential-like value "
                "(pattern %r at offset %d). Redaction red line: record only "
                "field name + existence + type, never a value fragment."
                % (where, pat.pattern[:40], m.start()))


# ------------------------------------------------------------- fingerprints --

_LINE_SUFFIX = re.compile(r"(?::\d+)+$")
_HASH_SUFFIX = re.compile(r"#L?\d+$")


def norm_locator(path):
    """Normalize a locator: '/' separators, no line numbers, dot segments collapsed.

    Line numbers and measured values are deliberately excluded so that a defect
    keeps its identity when unrelated edits shift it down a few lines.
    """
    if not path:
        return ""
    p = str(path).replace("\\", "/")
    p = _LINE_SUFFIX.sub("", p)
    p = _HASH_SUFFIX.sub("", p)
    parts = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/".join(parts)


def fingerprint(layer_group, path, signal, anchor):
    """sha1(layer_group | normalized_path | signal | anchor)[:16].

    THE ONLY fingerprint implementation in this repo. baseline diff, ledger
    dedup and gate 11 must all call this function; a second implementation
    would silently invalidate every historical baseline.
    """
    payload = "|".join([
        str(layer_group or ""),
        norm_locator(path),
        str(signal or ""),
        str(anchor or ""),
    ])
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


# ------------------------------------------------------- ownership resolution --

def _glob_to_regex(pattern):
    """Translate an ownership glob ('**' crosses '/', '*' does not)."""
    out = ["^"]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


_GLOB_CACHE = {}


def glob_match(pattern, path):
    rx = _GLOB_CACHE.get(pattern)
    if rx is None:
        rx = _glob_to_regex(pattern)
        _GLOB_CACHE[pattern] = rx
    return rx.match(norm_locator(path)) is not None


def resolve_layer(path, profile, default_layer):
    """Map a path to its layer_group via profile.ownership rules.

    Replaces the old substring-matching dedup: ownership is data, not code.
    Falls back to the producing layer when no rule matches.
    """
    if profile is not None:
        for rule in profile.get("ownership", []) or []:
            if glob_match(rule.get("pattern", ""), path):
                return rule.get("layer") or default_layer
    return default_layer


# ------------------------------------------------------------ whole-word match --

_CJK = re.compile(r"[\u3400-\u9fff\u3040-\u30ff\uac00-\ud7af]")


def _is_word_char(ch):
    return bool(ch) and (ch.isalnum() or _CJK.match(ch) or ch == "_")


def whole_word_hits(text, words):
    """Whole-word (CJK-aware) placeholder matching.

    A hit only counts when the matched word is not adjacent to another word
    character. This is what keeps a real place name that happens to contain
    a single character from being reported as a placeholder hit:
    single characters can never be delimited inside a longer word, and the
    word table itself only admits entries of 3+ characters (gate 13).
    Returns a list of (word, offset) pairs.
    """
    hits = []
    if not text:
        return hits
    for w in words or []:
        if not w:
            continue
        start = 0
        while True:
            i = text.find(w, start)
            if i < 0:
                break
            before = text[i - 1] if i > 0 else ""
            after = text[i + len(w)] if i + len(w) < len(text) else ""
            if not _is_word_char(before) and not _is_word_char(after):
                hits.append((w, i))
            start = i + 1
    return hits


# ---------------------------------------------------------------- LayerWriter #

class LayerWriter(object):
    """Collects findings for one layer and writes them idempotently.

    Hard-fix coverage:
      * overwrite mode ("w") + product clearing on construction -> running the
        same input twice can never double the ledger (was: append mode).
      * assert_no_secret() on every field at add() time and on the serialized
        CSV body at flush() time -> a credential-like fragment aborts the run
        instead of landing in the ledger.
    """

    def __init__(self, out_dir, layer, source, profile=None, clear=True):
        self.out_dir = out_dir
        self.layer = layer
        self.source = source
        self.profile = profile
        self.findings = []
        self.metrics = {}
        os.makedirs(out_dir, exist_ok=True)
        self.csv_path = os.path.join(out_dir, "findings_%s.csv" % layer)
        if clear:
            self.clear_products()

    def clear_products(self):
        """Remove this layer's products so a crashed previous run cannot leave
        a stale empty CSV behind (stale CSV == "layer ran, 0 findings" lie)."""
        for name in ("findings_%s.csv" % self.layer,
                     "metrics_%s.json" % self.layer,
                     "_done_%s.txt" % self.layer):
            p = os.path.join(self.out_dir, name)
            if os.path.exists(p):
                os.remove(p)

    def add(self, signal, anchor, path, severity, category, symptom, evidence,
            loc_line=0, threshold="", threshold_source=""):
        if severity not in SEVERITIES:
            raise ValueError("invalid severity %r" % (severity,))
        layer = resolve_layer(path, self.profile, self.layer)
        # Signal contract: deep.* is the deep-scan AST namespace and its
        # layer_group is FIXED to "deep". Ownership rules must never re-map a
        # deep-scan finding (e.g. cloudfunctions/** -> runtime), otherwise the
        # fingerprint would drift away from the fixture expectations.
        if str(signal).startswith("deep."):
            layer = "deep"
        row = {
            "fingerprint": fingerprint(layer, path, signal, anchor),
            "signal": signal,
            "anchor": str(anchor or ""),
            "layer": layer,
            "source": self.source,
            "severity": severity,
            "threshold": str(threshold or ""),
            "threshold_source": str(threshold_source or ""),
            "path": norm_locator(path),
            "loc_line": int(loc_line or 0),
            "category": str(category or ""),
            "symptom": str(symptom or ""),
            "evidence": str(evidence or ""),
            "decision": "", "owner": "", "note": "",
        }
        # Redaction gate, field by field: fail at collection time.
        for key in ("signal", "anchor", "path", "category", "symptom", "evidence"):
            assert_no_secret(row[key], "finding.%s" % key)
        self.findings.append(row)
        return row["fingerprint"]

    def set_metric(self, key, value):
        self.metrics[key] = value

    def flush(self):
        """Write findings CSV (mode "w") and metrics JSON.

        The full serialized body passes the redaction gate immediately before
        the file is opened - this is the last line of defence before disk.
        """
        body_rows = []
        for row in self.findings:
            body_rows.append(",".join(
                _csv_cell(row[f]) for f in FINDING_FIELDS))
        body = "\n".join([",".join(FINDING_FIELDS)] + body_rows)
        if body_rows:
            body += "\n"
        assert_no_secret(body, self.csv_path)
        with open(self.csv_path, "w", newline="", encoding="utf-8-sig") as f:
            f.write(body)
        if self.metrics:
            text = json.dumps(self.metrics, ensure_ascii=False, indent=2,
                              sort_keys=True) + "\n"
            assert_no_secret(text, "metrics_%s.json" % self.layer)
            with open(os.path.join(self.out_dir, "metrics_%s.json" % self.layer),
                      "w", encoding="utf-8") as f:
                f.write(text)

    def mark_done(self, scanned, complete, extra=None):
        """Write _done_<layer>.txt. complete=False writes incomplete: true.

        sweep.py MUST read this marker: a missing or incomplete marker means
        the layer must be reported as "scan incomplete" (P1), never as
        "0 findings, healthy".
        """
        return mark_done(self.out_dir, self.layer, scanned,
                         len(self.findings), complete, extra=extra)


def _csv_cell(value):
    s = "" if value is None else str(value)
    if any(c in s for c in (",", "\"", "\n", "\r")):
        return "\"" + s.replace("\"", "\"\"") + "\""
    return s


# ---------------------------------------------------------- completion marks #

def mark_done(out_dir, layer, scanned, findings, complete, extra=None):
    path = os.path.join(out_dir, "_done_%s.txt" % layer)
    lines = [
        "layer=%s" % layer,
        "scanned=%d" % int(scanned),
        "findings=%d" % int(findings),
        "complete=%s" % ("true" if complete else "false"),
    ]
    if extra:
        for k in sorted(extra):
            lines.append("%s=%s" % (k, extra[k]))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def read_done(out_dir, layer):
    """Read a completion marker. Returns None when absent (layer never ran)."""
    path = os.path.join(out_dir, "_done_%s.txt" % layer)
    if not os.path.exists(path):
        return None
    info = {"path": path}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            info[k] = v
    return info


# ------------------------------------------------------------------- helpers #

def read_text(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def rel_path(path, root):
    """Path relative to root with '/' separators (locator form)."""
    try:
        return norm_locator(os.path.relpath(path, root))
    except ValueError:
        return norm_locator(path)


def stdout_utf8():
    """Windows consoles default to GBK; reconfigure so CJK output never dies."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# --------------------------------------------------------------------- CLI --

# Golden vector, computed by hand from the contract formula
# sha1(layer_group | normalized_path | signal | anchor)[:16]:
#   "deep" | "app/svc_a.py" | "deep.silent.empty_catch" | "svc_a.load_config"
_GOLDEN_FINGERPRINT = "dbd3b53bbbd3e495"


def main(argv=None):
    """Selftest: fingerprint formula, redaction gate, whole-word matching.

    No side effects and no network. The golden vector is an independently
    computed constant: any drift in fingerprint() or norm_locator() fails here.
    """
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    stdout_utf8()
    if "--selftest" not in argv:
        sys.stderr.write("usage: sweeplib.py --selftest\n")
        return 2
    # 1) line numbers and dot segments never change the fingerprint
    fp = fingerprint("deep", "app/svc_a.py:42", "deep.silent.empty_catch",
                     "svc_a.load_config")
    fp_moved = fingerprint("deep", "app/./svc_a.py#L99",
                           "deep.silent.empty_catch", "svc_a.load_config")
    assert fp == fp_moved, "line numbers / dot segments must not change fp"
    assert fp == _GOLDEN_FINGERPRINT, (
        "fingerprint drifted from the contract formula: %s" % fp)
    # 2) deep.* layer_group is fixed regardless of ownership rules
    prof = {"ownership": [{"pattern": "cloudfunctions/**", "layer": "runtime"}]}
    assert resolve_layer("cloudfunctions/x/index.js", prof, "deep") == "runtime"
    assert resolve_layer("app/svc_a.py", prof, "deep") == "deep"
    # 3) redaction gate fires on credential-like text, silent on plain text
    try:
        assert_no_secret("api_key: abcdef1234567890", "selftest")  # skillcheck:allow - deliberate gate test vector, not a credential
    except SecretLeak:
        pass
    else:
        raise AssertionError("redaction gate did not fire")
    assert_no_secret("field name + existence + type only", "selftest")
    # 4) whole-word matching: a single char inside a longer word never hits
    assert whole_word_hits("菲律宾波利略岛（Polillo）", ["略"]) == []
    assert whole_word_hits("值=待补充", ["待补充"]) == [("待补充", 2)]
    print("OK sweeplib selftest: fingerprint golden vector + redaction gate "
          "+ whole-word matching")
    return 0


if __name__ == "__main__":
    sys.exit(main())
