# v2.0 Optimisation Guide

## Pipeline (before -> after)

```
BEFORE                                   AFTER
read file                                read file once
g++ -E   (macro scan)                    lexer pre-flight (delimiters, microseconds)
g++ -c   (symbol scan)                   token-based safety gate
g++      (real build, NO -W flags)       ONE build: -O2 + security warning profile (cached)
per error: re-scan whole file            parse: option tags, notes, re-anchoring, dedupe
load 37 MB pickle (2.0 s)                rules first; 170 ms numpy model only if needed
regex line-by-line security scan         token/taint security scan, once per file
                                         optimisation advice, once per file
```

## Modules

| Module | Role |
|---|---|
| `lexer.py` | Shared C++ lexer: tokens with positions, `blank_source`, delimiter check, call extraction |
| `diagnostics.py` | Compiler runner (limits, cache, process-group kill) + stderr parser |
| `build_cache.py` | Content-addressed JSON cache (schema-validated, LRU, atomic writes) |
| `taxonomy.py` | 33 categories, CWE table, `[-Wxxx]`/message rules, template normaliser |
| `error_classifier.py` | Hybrid classifier: rules -> compact ML with abstention |
| `security_analyzer.py` | Compiler findings + static/taint scan, CWE ids, SARIF-ready |
| `secure_fixer.py` | Verified auto-hardening |
| `perf_analyzer.py` | Optimisation advice |
| `pipeline.py` | One orchestrated analysis used by CLI/tests |
| `sarif.py` | SARIF 2.1.0 export |

## CLI

```bash
python src/main.py f.cpp                  # errors + security + optimisation advice
python src/main.py f.cpp -v               # + notes, context, timings
python src/main.py f.cpp --all            # + style/quality/follow-on diagnostics
python src/main.py f.cpp --format sarif   # CI / code scanning
python src/main.py f.cpp --fail-on high   # exit 2 if a finding >= high exists
python src/main.py f.cpp --harden         # verified fixes -> f.hardened.cpp + diff
python src/main.py --clear-cache f.cpp
```

Environment: `GSC_NO_CACHE=1`, `GSC_CACHE_DIR`, `GSC_ABSTAIN_BELOW` (default 0.70),
`GSC_BUILD_CPU_S`, `GSC_BUILD_MEM_MB`, `GSC_DISABLE_DATASET_LOGGING=1`.

## Re-training the classifier

```bash
pip install scikit-learn scipy
python src/error_classifier.py        # writes data/error_classifier.model.{json,npz}
```
Training reads `data/training_data.json` and `data/logged_diagnostics.jsonl`.

## Reproducing the numbers

```bash
python tests/test_audit_fixes.py      # original 16 regression tests
python tests/test_optimized.py        # 32 new tests
python benchmarks/eval_security.py    # recall / false positives
python benchmarks/pipeline_bench.py . # time + g++ invocations
```
See `benchmarks/RESULTS.md` for results and for which figures are tuned vs blind.

## Limitations (be aware)

* The static scan has no flow analysis: conditional initialisation and cross-function ownership
  are not detected; findings carry a `confidence` field - treat "Medium" as "review".
* The safety gate is best-effort, not a sandbox; this tool never executes compiled code.
* `-Wconversion` narrowing is classified (`narrowing_conversion`) but hidden by default as noise;
  use `--all` to see it. `<sys/...>` includes are blocked unless `ALLOW_SYS_INCLUDES=1`.
* Auto-hardening changes behaviour slightly (e.g. `fgets` keeps the newline); review the diff.
