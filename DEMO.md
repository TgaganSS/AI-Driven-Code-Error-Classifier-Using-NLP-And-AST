# Demo guide (about 10 minutes)

## Before you start (2 min, do this ahead of time)
```bash
unzip cd1_optimized.zip && cd cd1
pip install -r requirements.txt          # PyQt6, numpy  (+ sudo apt install g++ binutils)
python3 tests/test_optimized.py          # must print 32/32 passed
```
Optional side-by-side: extract the ORIGINAL zip somewhere and run `OLD_DIR=/path/to/old/cd1 ./run_demo.sh`.
Run `./run_demo.sh` - it pauses between steps; press ENTER to advance. Use a large terminal font.

## Talk track
| Step | Say | Point to |
|---|---|---|
| 0 | "It is a self-healing C++ compiler front-end: it compiles, explains errors, classifies them, assesses security, and auto-fixes. I optimised four things: detection, classification, security and speed." | |
| 1 Detection | "The original tool printed 'Compilation successful, Clean' for a null dereference because it passed no warning flags." | Category + CWE-476 + "100% via rule:-Wnull-dereference" |
| 2 Security | "Findings carry CWE ids and confidence. It follows user input (cin, argv) into dangerous calls - that is taint tracking." | Format-string, unvalidated index, new[]/delete mismatch |
| 3 Hardening | "Fixes are only kept if the program still compiles AND the finding disappears. It never edits your file unless --in-place." | The diff; remaining finding is honestly reported |
| 4 Optimization | "Code-level advice: exponential recursion, hidden O(n^2), copies, flushes." | fib, strlen-in-loop |
| 5 Speed | "One build instead of four, a cache, and a 2.9 MB model instead of 37 MB." | cold 0.35 s vs cached 0.01 s vs 2.9 s originally |
| 6 Explanation | "The original purpose still works." | |
| 7 Safety | "Dangerous code is blocked before any compiler runs." | CWE-78 |
| 8 CI | "SARIF output and exit codes let it gate pull requests." | exit code 2 |
| 9 Evidence | "16 original tests plus 32 new ones; measured results in benchmarks/RESULTS.md." | |

Optional live GUI: `python3 src/gui.py`, open `demo/04_syntax_error.cpp`, click Auto-Heal.

## Questions to expect (honest answers)
* **"Is 100% on your test set real?"** The corpus was written while building the analyzer, so it is tuned. On 20 unseen programs the first run scored 17/20 (85%) vs 9/20 for the old analyzer; gaps found were then fixed. Quote 85%.
* **"Why not just use cppcheck / clang-tidy?"** This ties compiler warnings, CWE classification, explanation, verified auto-fix and the healing loop into one pipeline; and it runs with only g++.
* **"Why rules + ML?"** Rules cover 96.5% of messages with ~99% precision; ML handles phrasing the rules miss (95% on unseen templates) and abstains when unsure instead of guessing.
* **"Limitations?"** No flow analysis (conditional initialisation, cross-function ownership); the safety gate is best-effort, not a sandbox; static findings have a confidence level - "medium" means review.
* **"Double free shows as 'Use After Free'?"** g++'s -Wuse-after-free covers both; the taxonomy labels it "Use after free / double free" with CWE-415 and CWE-416.
