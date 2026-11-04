# Measured results (reproducible)

Environment: g++ 13.3, Python 3.12, 26-file `test_cases/` set, single machine.
Reproduce with the scripts in this folder (`pipeline_bench.py`, `eval_security.py`) and
`python tests/test_optimized.py`.

| Metric | Before | After |
|---|---|---|
| Wall time per file (CLI) | 2.86 s | 0.40 s cold / 0.10 s warm cache |
| 26-file run | 74.5 s | 10.4 s cold / 2.5 s warm |
| g++ invocations per file | 2.9 | 1.3 cold / 0 warm |
| Classifier artifact | 37.5 MB pickle | 2.9 MB JSON+npz (no pickle) |
| Classifier load | 2,020 ms (+ sklearn import) | 170 ms (numpy only) |
| Real diagnostics classified correctly (103-item gold set, fine-grained) | 44.7 % (46/103) | 100 % (103/103; 98.1 % on first run) |
| ...of which security/correctness classes (49 items) | 6 / 49 | 49 / 49 |
| Compiler-flow-only bugs found (8) | 3 / 8 | 7 / 8 |
| Security corpus recall (48 vulnerable, tuned) | 17 / 48 (any finding) | 48 / 48 (correct CWE) |
| Security false positives (30 safe, tuned) | 6 / 30 | 0 / 30 |
| **Blind** security set, first run (20 vulnerable) | 9 / 20 (any finding) | 17 / 20 (correct CWE) |
| **Blind** security set false positives (12 safe), first run | 2 / 12 | 1 / 12 |
| ML fallback on UNSEEN message templates | n/a | 95.2 % accuracy; 97.8 % at 92 % coverage with abstention |

Note 1: the gold set exposed two rule-precedence bugs (fixed) and three narrowing warnings were re-labelled
into a new `narrowing_conversion` category after the first run, so the final 103/103 is *partly tuned*;
the first-run figure was 101/103. Treat the blind rows and the unseen-template ML row as the generalisation estimates.

Blind set after fixing the gaps it exposed: 19 / 20, 0 / 12 false positives (no longer blind).
