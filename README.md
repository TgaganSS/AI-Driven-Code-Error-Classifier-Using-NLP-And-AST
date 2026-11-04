# Green Self-Healing Compiler

An intelligent C++ diagnostic and auto-repair pipeline layered on top of `g++`.
It compiles your code, **explains** errors in plain English, **classifies** them (rules + a small ML model),
runs a **security analysis** (CWE-labelled findings), and **repairs** code automatically, keeping a fix only
if the compiler confirms it. No LLM, no API keys, no network access at run time.

> Project-Based Lab, Compiler Design, NIT Warangal. See `PBL_Report.md` for the full report and
> `project_explanation.md` for how each part maps to a compiler-design concept.

## Features
- Plain-English explanations (what happened / why / how to fix) for g++ errors and warnings
- Error classification: rules first, ML fallback that abstains when unsure
- Security findings with CWE ids, severity and confidence (use-after-free, format string, buffer overflow, ...)
- Self-healing loop: compile -> classify -> apply one rule-based fix -> recompile (max 10 attempts)
- `--harden`: security fixes that are verified (still compiles AND the finding disappears)
- Performance advice (exponential recursion, hidden O(n^2), pass-by-value, ...)
- Build cache, safety gate (blocks `system()` etc. before any compiler runs), SARIF output and CI exit codes
- PyQt6 GUI (editor, AST explorer, call graph, energy/carbon dashboard via CodeCarbon)

## Requirements
Linux (or WSL / Google Colab) with `g++` and `binutils`, and Python 3.10+.

```bash
sudo apt install g++ binutils python3 python3-pip
pip install -r requirements.txt
```

## Quick start
```bash
python3 src/main.py demo/01_null_deref.cpp           # explain + classify + security
python3 src/main.py demo/02_vulnerable.cpp           # CWE-labelled findings
python3 src/main.py demo/02_vulnerable.cpp --harden  # verified fixes -> 02_vulnerable.hardened.cpp
python3 tools/heal_demo.py demo/06_heal_semicolons.cpp   # watch the healing loop
python3 src/main.py file.cpp --fail-on high --format sarif   # CI usage (exit code 2 = fail)
```
Full guided demo: open `Final_Demo.ipynb` in Google Colab. Presenter notes: `PRESENTATION_GUIDE.md`.

## Tests
```bash
python3 tests/test_optimized.py     # 32 tests (tests needing g++ are SKIPPED if it is missing)
python3 tests/test_audit_fixes.py   # 16 tests
python3 benchmarks/eval_security.py # security recall / false positives
```

## Results
See `benchmarks/RESULTS.md`. The tuned test sets were written while building the tool, so the **blind** security
set (17/20 on the first run, 19/20 after fixes) is the honest estimate.

## Project layout
```
src/         pipeline: parser, normalizer, classifier, explainer, auto_healer, secure_fixer, security_analyzer, GUI, CLI
data/        trained classifier (JSON + npz, no pickle) and training data
demo/        small example files
tests/       automated tests
benchmarks/  evaluation scripts and results
tools/       doctor.py, heal_demo.py, make_big_tests.py
```

## Limitations
One translation unit at a time; healing is rule-based and stops on cases needing human intent (linker errors,
access errors, undeclared variables); no deep inter-procedural data-flow analysis; the safety gate is best-effort,
not a sandbox; requires g++ (tests skip without it).

## License
Add a license of your choice (for example MIT) before making the repository public.
