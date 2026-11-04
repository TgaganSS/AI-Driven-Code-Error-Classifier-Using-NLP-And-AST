"""
Regression + feature tests for the optimisation pass: detection, classification,
secure-code analysis, optimisation advice, hardening and safety.

Run:  python tests/test_optimized.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
os.environ.setdefault("GSC_DISABLE_DATASET_LOGGING", "1")
os.environ["GSC_CACHE_DIR"] = tempfile.mkdtemp(prefix="gsc_test_cache_")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import lexer                                   # noqa: E402
import diagnostics as D                        # noqa: E402
import compiler_runner as CR                   # noqa: E402
import taxonomy as T                           # noqa: E402
import error_classifier as EC                  # noqa: E402
import security_analyzer as SA                 # noqa: E402
import perf_analyzer as PA                     # noqa: E402
import secure_fixer as SF                      # noqa: E402
import pipeline as PL                          # noqa: E402


class Skip(Exception):
    """Raised when a test cannot run because a required system tool is missing."""


def needs(*tools):
    """Skip (visibly, never silently pass) a test whose system tools are not installed."""
    def deco(fn):
        def wrapper(*a, **k):
            missing = [t for t in tools if not shutil.which(t)]
            if missing:
                raise Skip("needs " + ", ".join(missing))
            return fn(*a, **k)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco

import security_corpus as CORPUS               # noqa: E402


def _tmp(code: str, name="t.cpp") -> str:
    d = tempfile.mkdtemp(prefix="gsc_t_")
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(code)
    return p


# ───────────────────────── lexer ─────────────────────────
def test_lexer_literals_and_comments():
    src = 'int big = 1\'000\'000; // system("x")\nauto r = R"x(system("y"))x"; /* gets(b) */\nint z;'
    toks = lexer.tokenize(src)
    assert not any(t.text in ("system", "gets") for t in toks if t.kind == lexer.IDENT)
    assert any(t.kind == lexer.NUMBER and t.text == "1'000'000" for t in toks)
    assert len(lexer.blank_source(src)) == len(src)


def test_lexer_delimiter_check_points_at_opener():
    probs = lexer.check_delimiters(lexer.tokenize("void f(){\n if(x){\n y=1;\n}\n"))
    assert probs and probs[0]["kind"] == "unclosed" and probs[0]["line"] == 1


# ───────────────────────── diagnostics ─────────────────────────
def test_option_tag_and_notes_parsed():
    d = D.parse_compiler_stderr(
        "a.cpp:3:5: warning: unused variable 'x' [-Wunused-variable]\n"
        "a.cpp:9:3: error: 'cout' was not declared in this scope\n"
        "a.cpp:2:1: note: 'std::cout' declared here\n", "a.cpp", 1)
    assert d[0]["option"] == "unused-variable"
    assert d[1]["notes"] and "declared here" in d[1]["notes"][0]["message"]


@needs("g++")
def test_system_header_diagnostic_reanchored_to_user_line():
    p = _tmp('#include <cstring>\n#include <cstdio>\nvoid ovf(){ char b[8]; strcpy(b, "this string is far too long"); puts(b); }\nint main(){ ovf(); }\n', "hdr.cpp")
    r = D.build(p, analysis=True, use_cache=False)
    w = [x for x in r.diagnostics if x["option"] and x["option"].startswith("array-bounds")]
    assert w, r.diagnostics
    assert w[0]["file"].endswith("hdr.cpp") and w[0]["line"] == 3 and w[0].get("anchored_from")


@needs("g++")
def test_template_errors_anchored_and_collapsed():
    p = _tmp("#include <vector>\n#include <algorithm>\nstruct S{int a;};\nint main(){ std::vector<S> v; std::sort(v.begin(), v.end()); }\n", "tpl.cpp")
    r = D.build(p, analysis=False, use_cache=False)
    errs = [x for x in r.diagnostics if x["type"] == "error"]
    assert len(errs) == 1 and errs[0]["line"] == 4 and errs[0]["file"].endswith("tpl.cpp"), errs
    assert errs[0]["instantiation"] is True


@needs("g++")
def test_build_cache_hit_is_much_faster():
    p = _tmp("#include <iostream>\nint main(){ std::cout << 1; }\n")
    a = D.build(p, analysis=True)
    b = D.build(p, analysis=True)
    assert not a.cached and b.cached and b.elapsed < a.elapsed / 5


@needs("g++")
def test_build_cache_invalidated_by_local_header_change():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "h.h"), "w").write("int v();\n")
    p = os.path.join(d, "m.cpp")
    open(p, "w").write('#include "h.h"\nint main(){ return v(); }\n')
    D.build(p, analysis=False)
    open(os.path.join(d, "h.h"), "w").write("int w();\n")           # header changed
    r = D.build(p, analysis=False)
    assert not r.cached


@needs("sh", "ps")
def test_timeout_kills_whole_process_group():
    # 31337 is a unique marker so unrelated `sleep` processes on the machine cannot cause a false alarm
    rc, _o, _e, to = D._run_limited(["sh", "-c", "sleep 31337 & sleep 31337; wait"], 1)
    assert to and rc == 124
    time.sleep(0.4)
    out = subprocess.run("ps -eo stat,args | awk '/sleep 31337/ && !/awk/ && $1 !~ /^Z/'", shell=True,
                         capture_output=True, text=True).stdout
    assert out.strip() == "", out


# ───────────────────────── safety gate ─────────────────────────
@needs("g++")
def test_gate_blocks_include_leak_and_token_paste():
    assert not CR._sanitize_code('#include "/etc/passwd"\nint main(){}', include_dir="/tmp")
    assert not CR._sanitize_code('#include "../../../etc/shadow"\nint main(){}', include_dir="/tmp/a/b")
    assert not CR._sanitize_code('#include <cstdlib>\n#define CAT(a,b) a##b\nint main(){ CAT(sys,tem)("x"); }')


def test_gate_no_false_positive_on_identifiers():
    ok = '#define ll long long\nint main(){ ll exec = 1; struct S{int system;} s; s.system = 1; return exec; }'
    assert CR._sanitize_code(ok)


def test_gate_rejects_oversized_source():
    assert not CR._sanitize_code("int x;\n" * 600_000)


# ───────────────────────── classifier ─────────────────────────
def test_gold_set_accuracy():
    gold = json.load(open(os.path.join(ROOT, "tests", "gold_diagnostics.json")))
    c = EC.ErrorClassifier()
    assert c.load()
    wrong = [(g["message"], g["expected"], c.classify(g["message"], dtype=g["type"]).category)
             for g in gold if c.classify(g["message"], dtype=g["type"]).category != g["expected"]]
    acc = 1 - len(wrong) / len(gold)
    assert acc >= 0.97, (acc, wrong)


def test_security_warnings_no_longer_other():
    c = EC.ErrorClassifier()
    for msg, want in [("format not a string literal and no format arguments [-Wformat-security]", "format_string"),
                      ("null pointer dereference [-Wnull-dereference]", "null_dereference"),
                      ("address of local variable 'x' returned [-Wreturn-local-addr]", "dangling_pointer")]:
        assert c.classify(msg).category == want


def test_model_is_pickle_free_and_small():
    m = EC._DEFAULT_MODEL_FILE
    assert m.endswith(".json") and os.path.exists(m[:-5] + ".npz")
    assert os.path.getsize(m) + os.path.getsize(m[:-5] + ".npz") < 8_000_000
    with open(m[:-5] + ".npz", "rb") as f:
        assert f.read(2) == b"PK"                       # zip container, not a pickle stream


def test_tampered_model_is_rejected():
    d = tempfile.mkdtemp()
    base = EC._DEFAULT_MODEL_FILE[:-5]
    shutil.copy(EC._DEFAULT_MODEL_FILE, os.path.join(d, "m.model.json"))
    # keep the same npz name referenced inside the json
    with open(os.path.join(d, "m.model.json")) as f:
        doc = json.load(f)
    shutil.copy(base + ".npz", os.path.join(d, doc["npz"]))
    assert EC.LinearTextModel.load(os.path.join(d, "m.model.json")) is not None
    with open(os.path.join(d, doc["npz"]), "ab") as f:
        f.write(b"tamper")
    assert EC.LinearTextModel.load(os.path.join(d, "m.model.json")) is None


def test_ml_abstains_on_gibberish():
    c = EC.ErrorClassifier()
    r = c.classify("zorp blarg quux flibber 42 wobble")
    assert r.uncertain or r.confidence < 0.9


def test_inference_does_not_import_sklearn():
    code = ("import sys; sys.path.insert(0, %r); import error_classifier as E; c=E.ErrorClassifier();"
            "c.classify('zzz unknown message'); print('sklearn' in sys.modules)" % os.path.join(ROOT, "src"))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip()
    assert out == "False", out


# ───────────────────────── security analyzer ─────────────────────────
def _scan(body: str):
    return SA.analyze_source(CORPUS.source_of(body), "/tmp/corpus.cpp")


def test_corpus_static_recall():
    miss = []
    total = 0
    for id_, exp, needs_compiler, body in CORPUS.VULN:
        if needs_compiler:
            continue
        total += 1
        if not any(set(f.cwe) & exp for f in _scan(body)):
            miss.append(id_)
    assert len(miss) <= max(1, total // 25), miss          # >= 96 % recall


def test_corpus_no_false_positives_on_safe_code():
    fp = [(i, [f.vulnerability_type for f in _scan(b)]) for i, b in CORPUS.SAFE if _scan(b)]
    assert not fp, fp


@needs("g++")
def test_compiler_only_bugs_found_via_pipeline():
    need = [v for v in CORPUS.VULN if v[2]]
    found = 0
    for id_, exp, _n, body in need:
        # (the gate rightly blocks <sys/...> headers, so use a header without them here)
        p = _tmp(CORPUS.source_of(body).replace("#include <sys/stat.h>\n", ""), id_ + ".cpp")
        r = PL.analyze_file(p, optimize=False, log=False, use_ast=False)
        if any(set(f.cwe) & exp for f in r.security_findings):
            found += 1
    assert found >= len(need) - 1, (found, len(need))


def test_taint_flow_command_injection_is_critical():
    f = SA.analyze_source('#include <cstdlib>\nint main(int c,char**v){ system(v[1]); }', "/tmp/a.cpp")
    assert any(x.severity == "Critical" and 78 in x.cwe for x in f)


def test_validated_index_not_flagged():
    f = _scan("void f(){ int a[10]; int i; cin >> i; if (i < 0 || i >= 10) return; a[i] = 1; }")
    assert not f


def test_cwe_and_sarif_export():
    import sarif
    f = _scan('void f(const char* s){ char b[8]; strcpy(b, "far too long for it"); puts(b); }')
    s = sarif.to_sarif(f)
    assert s["version"] == "2.1.0" and s["runs"][0]["results"]
    assert any("external/cwe/cwe-120" in r["properties"]["tags"] for r in s["runs"][0]["tool"]["driver"]["rules"])


# ───────────────────────── optimisation advice ─────────────────────────
def test_perf_patterns():
    cases = {
        "PERF-003": 'void f(const char* s){ for (size_t i = 0; i < strlen(s); i++) {} }',
        "PERF-002": 'int fib(int n){ if (n < 2) return n; return fib(n-1) + fib(n-2); }',
        "PERF-004": '#include <iostream>\nvoid f(int n){ for (int i=0;i<n;i++) std::cout << i << std::endl; }',
        "PERF-001": '#include <vector>\nint f(std::vector<int> v){ return 1; }',
    }
    for rule, code in cases.items():
        assert any(x.rule_id == rule for x in PA.analyze_performance(code, "/tmp/x.cpp")), rule


def test_perf_clean_code_has_no_advice():
    code = ('#include <vector>\nint f(const std::vector<int>& v){ int s=0; for (int x : v) s += x; return s; }')
    assert PA.analyze_performance(code, "/tmp/x.cpp") == []


# ───────────────────────── hardening ─────────────────────────
_HARDEN_SRC = r'''#include <iostream>
#include <cstdlib>
#include <cstring>
using namespace std;
void a(const char* s) {
    char b[8];
    strcpy(b, s);
    printf(s);
    char w[10];
    scanf("%s", w);
}
void m() {
    int* p = new int[10];
    p[0] = 1;
    delete p;
}
void l() {
    int arr[10];
    for (int i = 0; i <= 10; i++) arr[i] = 0;
}
int main() { return 0; }
'''


@needs("g++")
def test_hardener_applies_only_verified_fixes():
    p = _tmp(_HARDEN_SRC)
    before = SA.analyze_source(_HARDEN_SRC, p)
    r = SF.harden_source(_HARDEN_SRC, p)
    assert r.error is None and len(r.applied) >= 5
    assert len(r.remaining) < len(before)
    ok, why = SF._compiles(r.hardened, os.path.dirname(p))
    assert ok, why
    assert "snprintf(b, sizeof(b)" in r.hardened and "delete[] p" in r.hardened and "i < 10" in r.hardened


@needs("g++")
def test_hardener_refuses_non_compiling_source():
    r = SF.harden_source("int main( { return 0 }\n", "/tmp/bad.cpp")
    assert r.error and not r.changed


# ───────────────────────── pipeline / CLI ─────────────────────────
@needs("g++")
def test_null_dereference_no_longer_reported_clean():
    p = _tmp("int main(){ int* p = nullptr; *p = 10; return 0; }\n")
    r = PL.analyze_file(p, log=False, use_ast=False)
    assert any(f.vulnerability_type == "Null Pointer Dereference" for f in r.security_findings)
    assert r.visible()


def test_pipeline_blocks_dangerous_source_before_running_compiler():
    p = _tmp('#include <cstdlib>\nint main(){ system("ls"); }\n')
    r = PL.analyze_file(p, log=False, use_ast=False)
    assert r.blocked and r.error_count == 1


@needs("g++")
def test_pipeline_points_missing_brace_at_opener():
    p = _tmp("#include <iostream>\nint f(){\n  return 1;\nint main(){ return 0; }\n")
    r = PL.analyze_file(p, log=False, use_ast=False)
    assert any("never closed" in (e.explanation or "") for e in r.errors), [e.message for e in r.errors]


@needs("g++")
def test_cli_fail_on_exit_code():
    p = _tmp("int main(){ int* p = nullptr; *p = 1; return 0; }\n")
    env = dict(os.environ)
    r = subprocess.run([sys.executable, os.path.join(ROOT, "src", "main.py"), p, "--fail-on", "high", "-j"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 2, (r.returncode, r.stderr[-300:])
    json.loads(r.stdout)


def test_dataset_logger_only_logs_rule_labels():
    import dataset_logger as DL
    d = tempfile.mkdtemp()
    DL.LOG_FILE = os.path.join(d, "log.jsonl")
    DL.DATA_DIR = d
    DL._seen = None
    os.environ["GSC_DISABLE_DATASET_LOGGING"] = "0"
    try:
        class E: pass
        e = E(); e.message = "'foo' was not declared in this scope"; e.category = "name_resolution"
        e.source = "ml"; e.ast_node = ""
        DL.log_example(e)
        assert not os.path.exists(DL.LOG_FILE)                       # ML guess: not logged
        e.source = "rule:message"
        DL.log_example(e); DL.log_example(e)
        assert len(open(DL.LOG_FILE).read().splitlines()) == 1       # logged once (dedup)
    finally:
        os.environ["GSC_DISABLE_DATASET_LOGGING"] = "1"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    passed = skipped = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
            passed += 1
        except Skip as why:
            print(f"SKIP  {name}: {why}")
            skipped += 1
        except Exception as exc:                                           # noqa: BLE001
            import traceback
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
            traceback.print_exc(limit=3)
            failed += 1
    print(f"\n{passed}/{len(tests)} passed" + (f", {skipped} skipped (missing system tools)" if skipped else "")
          + (f", {failed} FAILED" if failed else ""))
    sys.exit(0 if failed == 0 else 1)
