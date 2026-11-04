#!/usr/bin/env python3
"""Environment check: python3 tools/doctor.py   (paste the whole output when asking for help)"""
import os, platform, shutil, subprocess, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ["GSC_NO_CACHE"] = "1"

def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}"

print("== system")
print("OS      :", platform.platform()); print("Python  :", sys.version.split()[0])
for mod in ("numpy", "PyQt6", "sklearn"):
    try: __import__(mod); print(f"{mod:8}: ok")
    except Exception as e: print(f"{mod:8}: MISSING ({e.__class__.__name__})")
for tool in ("g++", "clang++", "nm", "sh", "ps"):
    print(f"{tool:8}:", shutil.which(tool) or "NOT FOUND")
rc, out = run(["g++", "--version"]); print("g++ --version:", out.splitlines()[0] if out else "-")
print("g++ is clang? :", "clang" in out.lower())

print("\n== compiler flags (each tried alone on an empty program)")
import diagnostics as D
bad = []
src = os.path.join(tempfile.mkdtemp(), "e.cpp"); open(src, "w").write("int main(){return 0;}\n")
for f in D.analysis_flags():
    rc, o = run(["g++", f, "-fsyntax-only", src])
    if rc != 0 or "unknown" in o.lower() or "unrecognized" in o.lower():
        bad.append((f, o.splitlines()[0][:90] if o else f"exit {rc}"))
print("rejected flags:", "none" if not bad else "")
for f, o in bad: print("  ", f, "->", o)

print("\n== end-to-end build")
r = D.build(src, analysis=True, use_cache=False)
print("rc =", r.returncode, "| diagnostics =", len(r.diagnostics), "| nm available =", r.nm_available)
if r.returncode != 0: print("stderr:", r.stderr[:400])
print("\nIf anything above says NOT FOUND / MISSING / rejected, that is the cause.")
