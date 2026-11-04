#!/usr/bin/env python3
"""
Regression tests for the issues found in the v1 correctness audit.
Run:  python3 tests/test_audit_fixes.py      (or: pytest tests/)
Requires g++ (and PyQt6 for the heal-loop tests, headless).
"""
import os
import shutil
import subprocess
import sys
import tempfile
import warnings

warnings.filterwarnings("ignore")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["GSC_DISABLE_DATASET_LOGGING"] = "1"   # never touch data/training_data.json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from compiler_runner import _sanitize_code, run_cpp_compiler     # noqa: E402
from diagnostics import parse_compiler_stderr                    # noqa: E402
import auto_healer                                               # noqa: E402

LINK_FAIL = "int foo();\nint main(){ return foo(); }\n"


def _tmp_cpp(text):
    d = tempfile.mkdtemp(prefix="gsc_test_")
    p = os.path.join(d, "t.cpp")
    with open(p, "w") as f:
        f.write(text)
    return p


# ── 4.1 linker errors must never be reported as success ─────────────────────
def test_linker_error_is_reported():
    p = _tmp_cpp(LINK_FAIL)
    diags = run_cpp_compiler(p)
    assert diags, "linker failure produced an empty (=success) result"
    assert any("undefined reference" in d["message"] for d in diags)
    assert not os.path.exists(os.path.join(os.path.dirname(p), "a.out"))


def test_cli_exit_code_on_link_failure():
    p = _tmp_cpp(LINK_FAIL)
    r = subprocess.run([sys.executable, "-W", "ignore",
                        os.path.join(ROOT, "src", "main.py"), p],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "Compilation successful" not in r.stdout


def test_failed_build_never_empty():
    d = parse_compiler_stderr("some totally unknown tool output", "x.cpp", returncode=1)
    assert d and d[0]["type"] == "error"


def test_curly_quotes_normalised():
    d = parse_compiler_stderr("t.cpp:3:5: error: \u2018total\u2019 was not declared in this scope",
                              "t.cpp", 1)
    assert "'total'" in d[0]["message"]


# ── 4.2 undeclared-variable handler: reachable, dead dispatch entry gone ─────
def test_undeclared_variable_fix_reachable():
    src = "int main(){\n    total = 10;\n    return total;\n}\n"
    err = {"message": "'total' was not declared in this scope", "line": 2,
           "column": 5, "type": "error", "category": "name_resolution"}
    assert "auto total = 10;" in (auto_healer.attempt_fix(src, err) or "")
    assert "undeclared_variable" not in auto_healer._HANDLERS


# ── 4.3 unused_variable is fixable and no longer excluded ───────────────────
def test_unused_variable_not_excluded():
    assert "unused_variable" not in auto_healer.UNFIXABLE_CATEGORIES


def test_unused_variable_fix_preserves_side_effects():
    src = "int f();\nint main(){\n    int a = 5;\n    int b = f();\n    return 0;\n}\n"
    e1 = {"message": "unused variable 'a' [-Wunused-variable]", "line": 3, "type": "warning"}
    out = auto_healer.fix_unused_variable(src, e1)
    assert "int a = 5;" not in out                       # pure -> deleted
    e2 = {"message": "unused variable 'b' [-Wunused-variable]", "line": 4, "type": "warning"}
    out2 = auto_healer.fix_unused_variable(src, e2)
    assert "int b = f();" in out2 and "(void)b;" in out2  # call kept


# ── 4.4 sanitizer bypasses ──────────────────────────────────────────────────
def test_sanitizer_blocks_bypasses():
    blocked = [
        '#include <cstdlib>\nint main(){ system("x"); }',
        '#include <cstdlib>\nint main(){ auto p = &system; p("x"); }',
        '#include <cstdlib>\n#define RUN system\nint main(){ RUN("x"); }',
        '#include <cstdlib>\nint main(){ auto p = system; p("x"); }',
        '#include <cstdio>\nint main(){ popen("ls","r"); }',
        'int main(){ asm("nop"); }',
        '#include <sys/socket.h>\nint main(){}',
    ]
    for code in blocked:
        assert _sanitize_code(code) is False, code


def test_sanitizer_allows_benign():
    ok = [
        '#include <iostream>\nint main(){ std::cout << "hi"; }',
        '#include <iostream>\nint main(){ std::cout << "system(x)"; } // system("y")',
        '#include <bits/stdc++.h>\nint main(){ std::map<int,int> m; std::thread t([]{}); t.join(); }',
    ]
    for code in ok:
        assert _sanitize_code(code) is True, code


def test_sanitizer_respects_permission_flag():
    code = '#include <cstdlib>\nint main(){ system("true"); }'
    assert _sanitize_code(code, {"allow_system_calls": True}) is True


# ── 4.5 report/fixture consistency ──────────────────────────────────────────
def test_clean_baseline_has_zero_findings():
    from security_analyzer import analyze
    assert analyze(os.path.join(ROOT, "test_clean.cpp"), []) == []


def test_vulnerable_fixture_has_findings():
    from security_analyzer import analyze
    assert len(analyze(os.path.join(ROOT, "test_secure.cpp"), [])) >= 1


# ── 4.6 docs vs code ────────────────────────────────────────────────────────
def test_docs_match_max_attempts():
    import re
    code = open(os.path.join(ROOT, "src", "heal_loop.py")).read()
    n = re.search(r"^MAX_ATTEMPTS\s*=\s*(\d+)", code, re.M).group(1)
    for doc in ("DOCUMENTATION.md", "project_explanation.md", "PBL_Report.md"):
        txt = open(os.path.join(ROOT, doc)).read()
        for m in re.findall(r"MAX_ATTEMPTS\s*=\s*(\d+)", txt):
            assert m == n, f"{doc} says {m}, code says {n}"


# ── heal loop end-to-end (needs PyQt6) ──────────────────────────────────────
def _heal(text):
    from heal_loop import HealWorker
    from error_classifier import ErrorClassifier
    p = _tmp_cpp(text)
    w = HealWorker(p, ErrorClassifier())
    sig = []
    w.compile_clean.connect(lambda: sig.append("clean"))
    w.give_up.connect(lambda h: sig.append("give_up"))
    w._heal()
    return sig[-1] if sig else None, open(p).read(), p


def test_heal_loop_never_claims_clean_on_link_failure():
    sig, _, p = _heal(LINK_FAIL)
    assert sig == "give_up"
    assert not os.path.exists(os.path.join(os.path.dirname(p), "a.out"))


def test_heal_loop_missing_include_does_not_corrupt_cout():
    sig, out, _ = _heal('int main(){\n    std::cout << "hi";\n    return 0;\n}\n')
    assert "std::const" not in out
    assert sig == "clean" and "#include <iostream>" in out


def test_heal_loop_missing_semicolon():
    sig, out, _ = _heal('#include <iostream>\nint main(){\n    int x = 10\n'
                        '    std::cout << x;\n    return 0;\n}\n')
    assert sig == "clean" and "int x = 10;" in out


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"PASS  {name}")
        except Exception as e:                       # noqa: BLE001
            failed += 1; print(f"FAIL  {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
