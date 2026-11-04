# Changelog

## v2.0 - detection, classification, security & optimisation overhaul

Base idea unchanged (compile -> explain -> classify -> assess security -> auto-heal).
Measured results: `benchmarks/RESULTS.md`. Technical write-up: `OPTIMIZATION.md`.

### Error detection
- **Warnings are now actually detected.** The CLI passed *no* warning flags, so
  `int* p = nullptr; *p = 10;` printed "Compilation successful / Risk score 0 (Clean)".
  New `-O2` security profile (`-Wnull-dereference -Warray-bounds=2 -Wstringop-overflow=4
  -Wuse-after-free=3 -Wdangling-pointer=2 -Wformat-security -Wsign-conversion ...`),
  filtered to what the installed compiler supports.
- `[-Wxxx]` option tags parsed; `note:` lines attached to their diagnostic;
  diagnostics inside system headers (template errors, fortified `strcpy`) **re-anchored to the
  user's line**; duplicates collapsed; follow-on brace errors flagged `cascade`.
- New shared C++ **lexer** (`lexer.py`) replaces three divergent comment/string strippers;
  handles raw strings, digit separators, multi-line calls. Pre-flight delimiter check points at the
  *opening* brace that is never closed instead of the end of file.

### Classification
- New taxonomy (`taxonomy.py`): 33 categories with severity, CWE ids and legacy parents
  (healer/explainer/GUI keep working). Deterministic rules keyed on the warning flag and message
  templates cover 96.5 % of messages (99.35 % agreement with the dataset's specific labels).
- ML is now a *fallback* with **abstention** (was: every security warning -> `other` at 64-94 %).
  Trained on 5.8 k identifier-masked templates (not 67 k near-duplicates); 22.8 k mislabelled rows
  re-labelled by the rules.
- **No more pickle**: JSON + `.npz` with SHA-256 check, pure-numpy inference (37.5 MB -> 2.9 MB,
  2.0 s -> 0.17 s load, scikit-learn only needed for re-training, no version-mismatch retrains).

### Secure code
- `security_analyzer.py` rewritten on the lexer: per-function scopes, constant evaluation of array
  sizes, **taint tracking** (`cin`, `argv`, `getenv`, `fgets`, `scanf`, `recv` -> `system`, `printf`,
  `strcpy`, `memcpy`, indices, allocation sizes, file paths), CWE ids, rule ids, confidence.
  Stops flagging safe code (`strcpy` of a fitting literal, freed/returned `malloc`, any line
  containing "size"); finds definite overflows, off-by-one loops, `cin >> char[]`, `new[]`/`delete`
  mismatches, per-function double free / use-after-free, missing NULL checks, `malloc(strlen(s))`,
  hard-coded credentials and API keys, weak crypto/RNG, insecure temp files, TOCTOU, 0777.
- **Verified auto-hardening** (`secure_fixer.py`, `--harden`): token-precise fixes kept only if the
  program still compiles *and* the targeted finding disappears.
- SARIF 2.1.0 export (`--format sarif`) and CI gate (`--fail-on high`).

### Optimisation
- Pipeline: 2.86 s -> 0.40 s per file cold, 0.10 s warm; g++ invocations 2.9 -> 1.3 / 0 per file.
  One build instead of up to four, content-addressed build cache (invalidated by local-header
  edits), compiler-probe cache, lazy model, classification memo, security scan once per file
  (was once per *error*).
- `perf_analyzer.py`: code-level advice (exponential recursion, hidden O(n^2): `strlen` in loop
  condition / `find` in loop / `erase(begin())` / string re-concatenation, allocation in loops,
  pass-by-value of heavy types, `std::endl` flushes, unsynchronised iostream, ...) plus the
  compiler's own performance warnings.

### Safety of the tool itself
- Builds run under `ulimit` CPU/memory limits in their own process group, killed on timeout
  (`subprocess.run(timeout=)` left `cc1plus` **running**; verified).
- Gate additions: include-path confinement (`#include "/etc/passwd"` leaked file contents into
  compiler messages), source-size cap, token-pasting bypasses, per-rule reasons.
- Dataset logger: append-only JSONL, rule-labelled entries only (the old one stored the model's
  own guesses as ground truth, rewrote a 14.7 MB file per error, non-atomically).
- Static security analysis now also runs when the gate blocks a build (it only reads text).

### Tests
- `tests/test_optimized.py` (32 tests), `tests/gold_diagnostics.json` (103 real diagnostics),
  `tests/security_corpus.py` (48 vulnerable / 30 safe). Original 16 tests still pass.

### Known limitations
- No flow analysis in the static scan: conditional initialisation (`if (c) v = 1; return v;`) and
  cross-function ownership (member allocated in a constructor, wrongly released in the destructor)
  are not detected. The gate is a best-effort guard, not a sandbox.
- AST context still needs `clang++` (skipped automatically when absent).

## v1.1 — correctness-audit fixes

### Critical
- **Linker errors no longer reported as success.** New `src/diagnostics.py` is the
  single g++-stderr parser used by `compiler_runner.py` and `heal_loop.py`
  (previously two independent regexes, both blind to GNU ld output). Recognises
  `undefined reference`, `multiple definition`, `collect2`/`ld` failures, macOS
  `Undefined symbols`, and guarantees a non-zero exit can never yield an empty
  result. Classifier gained a rule-based `linker_error` fast-path.

### High
- **Dead / contradictory code paths.** Removed the unreachable
  `"undeclared_variable"` dispatch entry (`fix_undeclared_variable` itself is
  live via `fix_name_resolution`). `unused_variable` removed from
  `UNFIXABLE_CATEGORIES` so its handler can run; the handler now keeps
  initializers with side effects (uses a `(void)` cast instead of deleting).
- **Security pre-filter hardened.** `_sanitize_code` now strips comments/strings,
  scans macro-expanded code, and checks the compiled object for undefined
  references to `system/popen/exec*/fork/dlopen/dlsym/syscall`. Blocks
  `&system`, `auto p = system;`, and `#define RUN system`. Still a best-effort
  guard, not a sandbox.

### Medium
- `PBL_Report.md`: corrected the "clean baseline" claim (`test_secure.cpp` is a
  deliberately vulnerable sample); added a real clean baseline `test_clean.cpp`;
  replaced Table 3 with measured, reproducible numbers (`tests/evaluate.py`).
- `DOCUMENTATION.md`: `MAX_ATTEMPTS` 3 → 10 (matches code); documented the
  diagnostics parser, safety gate, tests.

### Notes
- Removed the no-op 8.8.8.8 reachability poll (and its per-5s `QThread`) from the GUI.
- No more stray `a.out`: every build writes to a private temp dir / `os.devnull`;
  committed `a.out`, `src/a.out`, `security_demo`, `.DS_Store` removed; `.gitignore` added.
- `clang++` / binutils documented as system dependencies in `requirements.txt`.
- Retrained `data/error_classifier.joblib` under scikit-learn 1.8 (100% prediction
  agreement with the old model on a 3,000-message sample and all fixture
  diagnostics); `load()` now auto-retrains on version mismatch.

### Additional bugs found and fixed while verifying
- **Locale bug:** under UTF-8 locales g++ prints curly quotes (`‘x’`); every
  downstream regex expected ASCII `'`, silently disabling most name-based
  auto-fixes. Compiler is now run with `LC_ALL=C` and quotes are normalised.
- **Keyword-typo healer corrupted code:** `cout` (edit distance 2 from `const`)
  was "healed" into `const`. Standard-library names and `::`-qualified names are
  now excluded; `'X' is not a member of 'std'` routes to the include fixer.
- **Classifier could not be retrained** on scikit-learn ≥ 1.7 (`multi_class`
  argument removed) — fixed.
- **Missing-semicolon healing** patched the wrong line for g++'s
  `expected ',' or ';' before 'X'` — now patches the preceding statement.
- Dataset logger can be disabled with `GSC_DISABLE_DATASET_LOGGING=1`.

### Tests
- `tests/test_audit_fixes.py` (16 regression tests) and `tests/evaluate.py`.
