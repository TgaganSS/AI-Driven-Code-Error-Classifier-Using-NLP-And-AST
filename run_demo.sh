#!/usr/bin/env bash
# Guided demo.  Press ENTER between steps.  DEMO_NOPAUSE=1 runs straight through.
# Optional: OLD_DIR=/path/to/original/cd1  -> also runs the ORIGINAL tool for side-by-side.
cd "$(dirname "$0")"
export GSC_DISABLE_DATASET_LOGGING=1 QT_QPA_PLATFORM=offscreen PYTHONWARNINGS=ignore
B=$'\033[1m'; C=$'\033[96m'; R=$'\033[0m'
step() { echo; echo "${C}${B}━━━ $1 ━━━${R}"; echo "${B}\$ $2${R}"; [ -z "$DEMO_NOPAUSE" ] && read -r -p "   (ENTER to run) " _; }
run()  { eval "$1"; }
rm -rf ~/.cache/gsc-build-cache 2>/dev/null

step "1. DETECTION: a bug the original tool called 'clean'" "python3 src/main.py demo/01_null_deref.cpp"
if [ -n "$OLD_DIR" ]; then echo "${B}--- ORIGINAL tool:${R}"; (cd "$OLD_DIR" && python3 src/main.py "$OLDPWD/demo/01_null_deref.cpp" | head -5); echo "${B}--- NEW tool:${R}"; fi
run "python3 src/main.py demo/01_null_deref.cpp | head -22"

step "2. CLASSIFICATION + SECURITY: CWE ids, severity, confidence, taint" "python3 src/main.py demo/02_vulnerable.cpp --no-optimize"
run "python3 src/main.py demo/02_vulnerable.cpp --no-optimize | sed -n '/critical,/,\$p'"

step "3. SECURE CODE: verified auto-hardening (kept only if it still compiles AND the finding disappears)" "python3 src/main.py demo/02_vulnerable.cpp --harden"
cp demo/02_vulnerable.cpp /tmp/_demo_vuln.cpp
run "python3 src/main.py /tmp/_demo_vuln.cpp --harden | head -45"

step "4. OPTIMIZATION: algorithmic advice" "python3 src/main.py demo/03_slow.cpp"
run "python3 src/main.py demo/03_slow.cpp | sed -n '/Optimization advice/,\$p'"

step "5. SPEED: cold build vs cached build (same file)" "python3 src/main.py demo/03_slow.cpp -v --no-optimize --no-cache   # then again, cached"
run "echo 'cold  :'; python3 src/main.py demo/03_slow.cpp -v --no-optimize --no-cache | grep timing; echo 'cached:'; python3 src/main.py demo/03_slow.cpp -v --no-optimize | grep timing; echo '(original tool: ~2.9 s per file, every time)'"

step "6. ERROR EXPLANATION (the original purpose)" "python3 src/main.py demo/04_syntax_error.cpp"
run "python3 src/main.py demo/04_syntax_error.cpp | head -24"

step "7. SAFETY GATE: dangerous code is never compiled" "python3 src/main.py demo/05_blocked.cpp"
run "python3 src/main.py demo/05_blocked.cpp | head -12"

step "8. CI INTEGRATION: SARIF + exit code" "python3 src/main.py demo/02_vulnerable.cpp --fail-on high --format sarif | head -c 400; echo \"exit=\$?\""
run "python3 src/main.py demo/02_vulnerable.cpp --fail-on high --format sarif | head -c 400; echo; python3 src/main.py demo/02_vulnerable.cpp --fail-on high >/dev/null; echo exit code = \$?"

step "9. EVIDENCE: tests + measured results" "python3 tests/test_audit_fixes.py && python3 tests/test_optimized.py && python3 benchmarks/eval_security.py"
run "python3 tests/test_audit_fixes.py | tail -1; python3 tests/test_optimized.py | tail -1; python3 benchmarks/eval_security.py; cat benchmarks/RESULTS.md | sed -n 7,24p"

echo; echo "${B}Optional live demo: python3 src/gui.py  -> open demo/04_syntax_error.cpp -> Auto-Heal${R}"
