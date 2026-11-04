#!/usr/bin/env python3
"""
build_dataset_from_tests.py
============================
Compiles every .cpp file in test_cases/, extracts the real g++ error messages,
labels them with the correct category (defined per filename), and writes them
into data/training_data.json in the format expected by error_classifier.py.

Also accepts the new category names introduced by the codenet dataset:
  syntax_error, name_resolution, type_error, missing_include, linker_error,
  redefinition, access_error, return_type_error, other
"""

import json
import os
import subprocess
import re
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DIR     = os.path.join(PROJECT_ROOT, "test_cases")
DATA_FILE    = os.path.join(PROJECT_ROOT, "data", "training_data.json")

# ── Ground-truth labels per test file ────────────────────────────────────────
FILE_LABELS = {
    "syntax_error.cpp":          "syntax_error",
    "missing_brace.cpp":         "syntax_error",
    "break_outside_loop.cpp":    "syntax_error",
    "continue_outside_loop.cpp": "syntax_error",
    "wrong_main_signature.cpp":  "syntax_error",
    "undeclared_var.cpp":        "name_resolution",
    "missing_header.cpp":        "missing_include",
    "no_matching_function.cpp":  "type_error",
    "function_mismatch.cpp":     "type_error",
    "type_error.cpp":            "type_error",
    "invalid_operands.cpp":      "type_error",
    "invalid_cast.cpp":          "type_error",
    "invalid_array_index.cpp":   "type_error",
    "invalid_use_of_void.cpp":   "type_error",
    "signed_unsigned_compare.cpp": "type_error",
    "sizeof_function.cpp":       "type_error",
    "pointer_misuse.cpp":        "type_error",
    "invalid_return_type.cpp":   "return_type_error",
    "missing_return.cpp":        "return_type_error",
    "redefination.cpp":          "redefinition",
    "multiple_definition.cpp":   "redefinition",
    "const_assignment.cpp":      "access_error",
    "null_dereference.cpp":      "other",
    "success.cpp":               None,   # compiles cleanly — skip
}

ERROR_PATTERN = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+)(?::(?P<col>\d+))?:\s*"
    r"(?P<type>error|warning|note):\s*(?P<message>.*)$"
)

def compile_file(path: str):
    """Run g++ and return list of (type, message, ast_node) tuples."""
    result = subprocess.run(
        ["g++", "-std=c++17", "-Wall", "-Wextra", path, "-o", os.devnull],
        capture_output=True, text=True
    )
    entries = []
    for line in result.stderr.splitlines():
        m = ERROR_PATTERN.match(line.strip())
        if m:
            entries.append({
                "error_type": m.group("type"),
                "message":    m.group("message").strip(),
                "line":       int(m.group("line")),
            })
    return entries


def build():
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)

    # Load existing data to extend, not overwrite
    existing = []
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE) as f:
                existing = json.load(f)
        except Exception:
            existing = []

    existing_keys = {
        (e.get("message", ""), e.get("category", ""))
        for e in existing
    }

    new_entries = []
    stats = {}

    for fname, category in FILE_LABELS.items():
        if category is None:
            continue

        fpath = os.path.join(TEST_DIR, fname)
        if not os.path.exists(fpath):
            print(f"  [SKIP] {fname} — file not found")
            continue

        errors = compile_file(fpath)
        if not errors:
            print(f"  [WARN] {fname} — no errors captured")
            continue

        added = 0
        for e in errors:
            if e["error_type"] not in ("error", "warning"):
                continue
            key = (e["message"], category)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            entry = {
                "message":      e["message"],
                "category":     category,
                "ast_node":     "",
                "explanation":  "",
                "suggestion":   "",
                "confidence":   1.0,
            }
            new_entries.append(entry)
            stats[category] = stats.get(category, 0) + 1
            added += 1

        print(f"  [OK]   {fname:<35} → {category:<22} ({added} new errors)")

    combined = existing + new_entries
    with open(DATA_FILE, "w") as f:
        json.dump(combined, f, indent=2)

    print(f"\nDataset saved → {DATA_FILE}")
    print(f"Total entries : {len(combined)}")
    print(f"New entries   : {len(new_entries)}")
    print(f"\nClass distribution:")
    all_categories = {}
    for e in combined:
        c = e.get("category", "unknown")
        all_categories[c] = all_categories.get(c, 0) + 1
    for cat, count in sorted(all_categories.items(), key=lambda x: -x[1]):
        print(f"  {cat:<25} {count:>4}")

    return len(combined)


if __name__ == "__main__":
    print("Building dataset from test cases...\n")
    total = build()
    if total < 2:
        print("\nERROR: Not enough data to train. Add more test cases.", file=sys.stderr)
        sys.exit(1)
    print("\nDone.")
