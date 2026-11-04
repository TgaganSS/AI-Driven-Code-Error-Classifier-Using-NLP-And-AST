#!/usr/bin/env python3
"""
prepare_training_data.py
========================
Reads the criyle/codenet-compile-errors HuggingFace Arrow dataset,
filters to C/C++ submissions only, parses each compiler_output to
extract individual error/warning messages, classifies each message
into a category, and writes data/training_data.json.

Usage:
    python3 src/prepare_training_data.py \
        --snapshot /Users/chaitanyabhagat/.cache/huggingface/hub/\
datasets--criyle--codenet-compile-errors/snapshots/cb28713ad5627f3d025713e0de6295e0eef0b5a8

No synthetic data is generated — every entry comes directly from the dataset.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter
from typing import Optional

import pyarrow as pa
import pyarrow.ipc as ipc

# ── target output ────────────────────────────────────────────────────────────
_PROJECT_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OUTPUT_FILE    = os.path.join(_PROJECT_ROOT, "data", "training_data.json")

# ── language labels to include ───────────────────────────────────────────────
# We only want C++ examples to avoid noise from other languages.
CPP_LANGS = {"C++"}

# ── GCC/G++ error line pattern ───────────────────────────────────────────────
# Matches:  filename:line:col: error: message
#           filename:line: error: message            (no column)
#           filename: In function 'foo':             (context lines — skip)
_ERROR_RE = re.compile(
    r"^[^\s:][^:]*:\d+(?::\d+)?:\s*"
    r"(?P<severity>error|warning|note|fatal error):\s*"
    r"(?P<message>.+)$"
)

# ── category classification rules ────────────────────────────────────────────
# Evaluated in order; first match wins.
_RULES = [
    # missing_include — #include failures
    (re.compile(
        r"No such file or directory"
        r"|fatal error:.*\.h[>']?"
        r"|cannot open (source|include) file"
        r"|file not found"
        r"|compilation terminated",
        re.I), "missing_include"),

    # redefinition — duplicate definitions
    (re.compile(
        r"redefinition of"
        r"|already defined"
        r"|previous definition"
        r"|multiple definition",
        re.I), "redefinition"),

    # access_error — const / private / protected violations
    (re.compile(
        r"read-only"
        r"|cannot assign to"
        r"|is private"
        r"|is protected"
        r"|member is inaccessible"
        r"|assignment of read-only"
        r"|discards qualifiers"
        r"|cannot modify"
        r"|const\b.*\bqualified",
        re.I), "access_error"),

    # return_type_error — return value / void mismatches
    (re.compile(
        r"cannot convert.* in return"
        r"|return.* incompatible type"
        r"|return type.*mismatch"
        r"|void.*return.*value"
        r"|non-void.* returns"
        r"|return-type"
        r"|return statement.*void"
        r"|returning.* from.*incompatible"
        r"|must return 'int'"
        r"|main.*must return"
        r"|function.*should return",
        re.I), "return_type_error"),

    # linker_error — undefined symbols
    (re.compile(
        r"undefined reference"
        r"|undefined symbol"
        r"|unresolved external"
        r"|linker command failed"
        r"|ld returned",
        re.I), "linker_error"),

    # name_resolution — undeclared / out-of-scope identifiers
    (re.compile(
        r"was not declared in this scope"
        r"|undeclared"
        r"|use of undeclared identifier"
        r"|unknown type name"
        r"|identifier.*not found"
        r"|is not (a member|defined)"
        r"|did you mean"
        r"|implicit declaration of function",
        re.I), "name_resolution"),

    # type_error — type mismatches, conversions, overloads, pointer ops
    (re.compile(
        r"cannot convert"
        r"|invalid conversion"
        r"|incompatible type"
        r"|no matching function"
        r"|no viable"
        r"|invalid operands"
        r"|ambiguous"
        r"|does not match"
        r"|overload.*not viable"
        r"|wrong number of"
        r"|cannot be used"
        r"|invalid use of"
        r"|operand.*type"
        r"|narrowing conversion"
        r"|implicit conversion"
        r"|cannot initialize"
        r"|array subscript is not"
        r"|indirection requires pointer"
        r"|invalid application of 'sizeof'"
        r"|pointer operand"
        r"|subscript.*not.*integer"
        r"|invalid type argument"
        r"|is not a pointer"
        r"|cannot take address"
        r"|initializing.*incompatible"
        r"|assigning.*incompatible"
        r"|rvalue of type"
        r"|lvalue of type"
        r"|error:.*\btype\b",
        re.I), "type_error"),

    # syntax_error — parser / token errors
    (re.compile(
        r"expected"
        r"|parse error"
        r"|syntax error"
        r"|unexpected"
        r"|unterminated"
        r"|stray"
        r"|unmatched"
        r"|missing terminating"
        r"|at end of input"
        r"|before.*token"
        r"|illegal start"
        r"|not a statement"
        r"|extraneous",
        re.I), "syntax_error"),

    # other — catch-all
    (re.compile(r".*"), "other"),
]


def classify_message(message: str) -> str:
    for pattern, category in _RULES:
        if pattern.search(message):
            return category
    return "other"


def extract_errors(compiler_output: str):
    """
    Parse raw GCC/G++ output and return list of (severity, message) tuples
    for lines that are genuine error/warning diagnostics (skip note / context lines).
    """
    results = []
    for line in compiler_output.splitlines():
        m = _ERROR_RE.match(line.strip())
        if not m:
            continue
        severity = m.group("severity").lower()
        if "note" in severity:
            continue
        message = m.group("message").strip()
        # Strip pointer caret lines ("   ^~~~~") that sometimes bleed through
        if re.match(r"^\s*\^", message):
            continue
        results.append((severity, message))
    return results


def load_arrow_shards(snapshot_dir: str):
    """Yield (language, compiler_output) for every row in all Arrow shards."""
    shards = sorted(
        f for f in os.listdir(snapshot_dir)
        if f.endswith(".arrow")
    )
    if not shards:
        raise FileNotFoundError(f"No .arrow files found in: {snapshot_dir}")

    print(f"Found shards: {shards}")
    for shard in shards:
        path = os.path.join(snapshot_dir, shard)
        print(f"  Reading {shard} ...", flush=True)
        with pa.memory_map(path, "r") as f:
            reader = ipc.open_stream(f)
            while True:
                try:
                    batch = reader.read_next_batch()
                except StopIteration:
                    break
                langs   = batch.column("language").to_pylist()
                outputs = batch.column("compiler_output").to_pylist()
                for lang, out in zip(langs, outputs):
                    yield lang, out


def build(snapshot_dir: str, max_per_category: int = 50_000) -> None:
    os.makedirs(os.path.dirname(_OUTPUT_FILE), exist_ok=True)

    # Dedup by (normalized_message, category)
    seen        = set()
    entries     = []
    cat_counts  = Counter()
    total_rows  = 0
    skipped     = 0

    for lang, compiler_output in load_arrow_shards(snapshot_dir):
        total_rows += 1

        if lang not in CPP_LANGS:
            skipped += 1
            continue
        if not compiler_output or not compiler_output.strip():
            skipped += 1
            continue

        errors = extract_errors(compiler_output)
        for severity, message in errors:
            # Remove leading file path / line noise from message for clean storage
            clean = re.sub(r"^\s*(error|warning|fatal error):\s*", "", message, flags=re.I).strip()
            if not clean or len(clean) < 4:
                continue

            category = classify_message(clean)

            # Per-category cap to keep the dataset balanced
            if cat_counts[category] >= max_per_category:
                continue

            key = (clean.lower(), category)
            if key in seen:
                continue
            seen.add(key)

            entries.append({
                "message":     clean,
                "category":    category,
                "ast_node":    "",
                "explanation": "",
                "suggestion":  "",
                "confidence":  1.0,
            })
            cat_counts[category] += 1

        if total_rows % 50_000 == 0:
            print(f"  Processed {total_rows:,} rows | {len(entries):,} unique entries so far …")

    # Write
    with open(_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

    # Report
    print(f"\n{'═'*55}")
    print(f"  Dataset written → {_OUTPUT_FILE}")
    print(f"{'─'*55}")
    print(f"  Total Arrow rows  : {total_rows:>10,}")
    print(f"  Non-C/C++ skipped : {skipped:>10,}")
    print(f"  Unique entries    : {len(entries):>10,}")
    print(f"\n  Per-category breakdown:")
    for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(40, cnt // max(1, max(cat_counts.values()) // 40))
        print(f"    {cat:<22} {cnt:>7,}  {bar}")
    print(f"{'═'*55}\n")


def main():
    parser = argparse.ArgumentParser(description="Prepare training_data.json from codenet Arrow files")
    parser.add_argument(
        "--snapshot",
        required=True,
        help="Path to the HuggingFace snapshot directory containing .arrow files",
    )
    parser.add_argument(
        "--max-per-category",
        type=int,
        default=50_000,
        help="Maximum examples per category (default: 50000)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.snapshot):
        print(f"ERROR: snapshot directory not found: {args.snapshot}", file=sys.stderr)
        sys.exit(1)

    print(f"Source : {args.snapshot}")
    print(f"Output : {_OUTPUT_FILE}")
    print(f"Cap    : {args.max_per_category:,} per category\n")

    build(args.snapshot, max_per_category=args.max_per_category)


if __name__ == "__main__":
    main()
