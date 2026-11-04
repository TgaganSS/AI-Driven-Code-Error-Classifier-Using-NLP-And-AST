# Presentation guide (read this top to bottom, assume you know nothing)

## 1. What your project is, in plain words
When a C++ program has a mistake, the compiler (g++) prints a short, cryptic message.
**Your tool sits on top of g++ and does five extra things:**
1. **Explains** the error in plain English (what happened, why, how to fix).
2. **Classifies** it (syntax error, null pointer, buffer overflow...) using rules + a small machine-learning model.
3. **Checks security**: gives each problem an official CWE number, a severity and a confidence level.
4. **Fixes it automatically**, but only keeps a fix if the program still compiles AND the problem is gone.
5. **Stays safe and fast**: dangerous code is blocked before compiling; results are cached (0.4 s -> 0.01 s).

**One-sentence pitch:** "A self-healing C++ compiler front-end: it compiles, explains, classifies, security-checks and auto-repairs, in one pipeline that needs only g++."

## 2. Why this fits a Compiler Design course (SAY THIS, it earns marks)
| Compiler concept | Where it is in your project |
|---|---|
| Lexical analysis (scanner, finite automaton) | `error_parser.py` regex turns g++ output into tokens; `lexer.py` |
| Intermediate representation | `models.py` `CompilerError` object passed between phases |
| Token normalisation / canonical form | `error_normalizer.py` |
| Semantic analysis | `error_classifier.py` (rules + ML) |
| Optimisation passes | `perf_analyzer.py` (exponential recursion, hidden O(n^2)) |
| Source-to-source transformation | `auto_healer.py`, `secure_fixer.py` |
| Fixed-point iteration | `heal_loop.py` repeats until clean or stuck (max 10 tries) |
| Pre-processor guard | `compiler_runner.py` `_sanitize_code()` |

## 3. Before the day (do it twice)
1. Go to colab.research.google.com, sign in, **New notebook**, then File > **Upload notebook** and pick `Demo_Notebook.ipynb`.
2. Left side: click the folder icon, then upload **`cd1_final.zip`**.
3. Click **Runtime > Run all**. Wait ~3 minutes. Everything should run with no red errors.
4. Keep that finished notebook open in a browser tab on the day. If the Wi-Fi dies you still have the outputs on screen.
5. Take screenshots of the key outputs as a backup (null-deref explanation, vulnerable file findings, 32/32 line).

## 4. The 5-6 minute demo (follow the notebook headings)
| Step | You say | They should see |
|---|---|---|
| Tests | "48 automated tests, all passing on Linux with g++." | `32/32 passed` and `16/16 passed` |
| Detection | "The original tool said 'success' on a null dereference. Mine reports it." | CWE-476, High risk |
| Security | "Each finding has a CWE id, severity, confidence." | CWE-134, CWE-415/416 etc. |
| Hardening | "A fix is kept only if it still compiles and the issue disappears." | The diff |
| Explanation | "The original purpose: plain-English help for a syntax error." | What / Why / How to fix |
| Speed | "2.9 s per file originally; 0.4 s cold, 0.01 s cached." | two timing lines |
| Safety gate | "system() is blocked before any compiler runs." | Security Error message |
| CI | "Exit code 2 fails a build; SARIF works with GitHub." | `exit code = 2` |
| Numbers | "Tuned set 48/48; unseen blind set 19/20 after fixes (17/20 first run)." | eval output |

## 5. Suggested slides (6 slides)
1. Problem: compiler errors are cryptic. 2. Idea + pipeline diagram (the mermaid graph in `project_explanation.md`).
3. Mapping to compiler-design phases (table in section 2). 4. Live demo (the notebook). 5. Results table (`benchmarks/RESULTS.md`).
6. Limitations + future work.

## 6. Questions the professor may ask (honest answers)
* **Is 100% real?** The test set was written while building the tool, so it is tuned. On 20 unseen programs the first run scored 17/20 (vs 9/20 for the old version). Quote the blind number.
* **Why not cppcheck / clang-tidy?** Ours ties warnings, CWE labels, explanation, verified auto-fix and the repair loop into one pipeline that needs only g++.
* **Why rules AND machine learning?** Rules cover ~96% of messages with ~99% precision; the ML model handles unusual wording (95% on unseen templates) and says "unsure" instead of guessing.
* **Limitations?** No deep data-flow analysis (conditional initialisation, cross-function ownership). The safety gate is best-effort, not a sandbox. "Medium" confidence findings need human review.
* **Why does it run on Colab?** The project targets Linux (g++, nm, sh). My Windows laptop has no g++ (network blocked WSL), so I demo on Linux. On Windows the tests that need g++ show as SKIPPED, not silently passed.
* **Double free shows as "use after free"?** g++'s warning covers both; the label says use-after-free / double free with CWE-415 and CWE-416.

## 7. Do NOT
* Do not say "100% accurate" or "finds every bug".
* Do not say you wrote parts you can't explain. Read `project_explanation.md` once and be able to describe each module in one sentence.
* Do not demo the GUI live unless you've tested it on that exact machine (Colab has no screen).
